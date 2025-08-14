from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from collections import defaultdict, Counter
import argparse, re, time, threading, os, json
import plotly.graph_objs as go
from plotly.offline import plot

# ---------- ARGS ----------
parser = argparse.ArgumentParser(description="Mini Network Threat Radar (Live Dashboard)")
parser.add_argument('--proto', type=str, help='Filter by protocol: tcp, udp, icmp')
parser.add_argument('--port', type=int, help='Filter by source or dest port')
parser.add_argument('--host', type=str, help='Regex to match IP address or hostname')
parser.add_argument('--report', type=str, default="report.html", help='Report HTML filename')
parser.add_argument('--json', type=str, default=None, help='Optional JSON metrics output path (written each refresh)')
parser.add_argument('--live', action='store_true', help='Continuously refresh the HTML report while capturing')
parser.add_argument('--interval', type=int, default=10, help='Seconds between live report refreshes')
args = parser.parse_args()

# ---------- CONSTANTS / MAPS ----------
PROTO_MAP = defaultdict(lambda: "UNKNOWN", {1: "ICMP", 6: "TCP", 17: "UDP"})
STD_PORTS = {80, 443, 22, 25, 53, 123}  # http, https, ssh, smtp, dns, ntp

# ---------- STATE ----------
packet_count = 0
proto_counter = Counter()
ip_counter_src = Counter()
ip_counter_dst = Counter()
dns_queries = Counter()
alerts = []
scan_tracker = defaultdict(list)  # src_ip -> timestamps of SYNs
state_lock = threading.Lock()
stop_event = threading.Event()

# ---------- HELPERS ----------
def is_random_domain(domain: str) -> bool:
    # crude DGA-ish heuristic: low vowel ratio + long label
    label = domain.split('.')[0]
    if not label:
        return False
    vowels = len(re.findall(r'[aeiou]', label.lower()))
    ratio = vowels / max(1, len(label))
    return ratio < 0.3 and len(label) > 12

def log_alert(msg: str):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    with state_lock:
        alerts.append(f"[{ts}] {msg}")
    print(f"\033[91m[ALERT]\033[0m {msg}")

def safe_write(path: str, data: str):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, path)

# ---------- PACKET HANDLER ----------
def process_packet(packet):
    global packet_count
    if IP not in packet:
        return

    ip_layer = packet[IP]
    src, dst = ip_layer.src, ip_layer.dst
    proto_name = PROTO_MAP[ip_layer.proto]

    # filters first (fast-fail)
    if args.proto:
        if args.proto.lower() == 'tcp' and not packet.haslayer(TCP): return
        if args.proto.lower() == 'udp' and not packet.haslayer(UDP): return
        if args.proto.lower() == 'icmp' and not packet.haslayer(ICMP): return

    if args.port:
        if TCP in packet or UDP in packet:
            t = packet[TCP] if TCP in packet else packet[UDP]
            if args.port not in (t.sport, t.dport):
                return
        else:
            return

    if args.host:
        pattern = re.compile(args.host)
        matched = pattern.search(src) or pattern.search(dst)
        if not matched and packet.haslayer(DNSQR):
            q = packet[DNSQR].qname.decode(errors='ignore')
            matched = bool(pattern.search(q))
        if not matched:
            return

    with state_lock:
        packet_count += 1
        proto_counter[proto_name] += 1
        ip_counter_src[src] += 1
        ip_counter_dst[dst] += 1

    # anomalies: unusual ports + port scan + suspicious DNS
    if TCP in packet or UDP in packet:
        t = packet[TCP] if TCP in packet else packet[UDP]
        sport, dport = t.sport, t.dport

        if proto_name == "TCP" and sport not in STD_PORTS and dport not in STD_PORTS:
            log_alert(f"Unusual TCP port {sport}->{dport} from {src} to {dst}")

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            # Scapy makes flags comparable to string or int; 'S' means SYN only
            if flags == 'S' or int(flags) & 0x02:  # SYN bit
                now = time.time()
                with state_lock:
                    scan_tracker[src].append(now)
                    scan_tracker[src] = [t for t in scan_tracker[src] if now - t < 3]
                    if len(scan_tracker[src]) > 10:
                        log_alert(f"Possible Port Scan from {src} ({len(scan_tracker[src])} SYNs/3s)")

    if packet.haslayer(DNSQR):
        q = packet[DNSQR].qname.decode(errors='ignore')
        with state_lock:
            dns_queries[q] += 1
        if is_random_domain(q):
            log_alert(f"Suspicious DNS (possible DGA): {q} from {src}")

    # optional console line
    out = f"[IP] {src} -> {dst} | Protocol: {proto_name}"
    if TCP in packet or UDP in packet:
        t = packet[TCP] if TCP in packet else packet[UDP]
        out += f" | Ports: {t.sport}->{t.dport}"
    if packet.haslayer(DNSQR):
        out += f" | DNS: {packet[DNSQR].qname.decode(errors='ignore')}"
    # keep console noise reasonable
    print(out)

# ---------- REPORT ----------
def build_figures(snapshot):
    # Protocol usage
    proto_fig = go.Figure([go.Bar(x=list(snapshot['proto'].keys()), y=list(snapshot['proto'].values()))])
    proto_fig.update_layout(title="Protocol Usage", xaxis_title="Protocol", yaxis_title="Count")

    # Top Source IPs
    src_items = snapshot['top_src']
    src_fig = go.Figure([go.Bar(x=[ip for ip, _ in src_items], y=[cnt for _, cnt in src_items])])
    src_fig.update_layout(title="Top Source IPs", xaxis_title="IP", yaxis_title="Packets Sent")

    # Top DNS
    dns_items = snapshot['top_dns']
    dns_fig = go.Figure([go.Bar(x=[d for d, _ in dns_items], y=[cnt for _, cnt in dns_items])])
    dns_fig.update_layout(title="Top DNS Queries", xaxis_title="Domain", yaxis_title="Count")

    return proto_fig, src_fig, dns_fig

def take_snapshot():
    with state_lock:
        snap = {
            "ts": time.strftime('%Y-%m-%d %H:%M:%S'),
            "packets": packet_count,
            "proto": dict(proto_counter),
            "top_src": ip_counter_src.most_common(10),
            "top_dst": ip_counter_dst.most_common(10),
            "top_dns": dns_queries.most_common(10),
            "alerts": list(alerts)[-200:],  # cap
        }
    return snap

def write_json(snapshot):
    if not args.json:
        return
    try:
        safe_write(args.json, json.dumps(snapshot, indent=2))
    except Exception as e:
        print(f"[warn] failed writing json: {e}")

def generate_report(live=False):
    snap = take_snapshot()
    proto_fig, src_fig, dns_fig = build_figures(snap)

    refresh_tag = f'<meta http-equiv="refresh" content="{args.interval}">' if live else ''
    title = "Network Threat Radar Report"
    css = """
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 20px; }
    .card { border: 1px solid #e5e7eb; border-radius: 14px; padding: 16px; margin-bottom: 18px; box-shadow: 0 1px 6px rgba(0,0,0,.04); }
    h1 { margin-top: 0; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
    ul { margin-top: 8px; }
    """

    html = f"""
    <html>
      <head>
        <meta charset="utf-8">
        {refresh_tag}
        <title>{title}</title>
        <style>{css}</style>
      </head>
      <body>
        <h1>{title}</h1>
        <div class="card">
          <b>Snapshot:</b> {snap['ts']} &nbsp; | &nbsp;
          <b>Total Packets:</b> {snap['packets']}
        </div>
        <div class="card">
          <h2>Alerts</h2>
          {"<ul>" + "".join(f"<li>{a}</li>" for a in snap['alerts']) + "</ul>" if snap['alerts'] else "No alerts triggered."}
        </div>
        <div class="card">
          <h2>Protocol Usage</h2>
          {plot(proto_fig, output_type='div', include_plotlyjs='cdn')}
        </div>
        <div class="card">
          <h2>Top Source IPs</h2>
          {plot(src_fig, output_type='div', include_plotlyjs=False)}
        </div>
        <div class="card">
          <h2>Top DNS Queries</h2>
          {plot(dns_fig, output_type='div', include_plotlyjs=False)}
        </div>
        <div class="card">
          <h2>Top Dest IPs (Table)</h2>
          {"<ol>" + "".join(f"<li><code>{ip}</code> — {cnt} pkts</li>" for ip,cnt in snap['top_dst'][:10]) + "</ol>" if snap['top_dst'] else "No destination data yet."}
        </div>
      </body>
    </html>
    """
    try:
        safe_write(args.report, html)
    except Exception as e:
        print(f"[warn] failed writing report: {e}")

    write_json(snap)

# ---------- LIVE LOOP ----------
def live_writer_loop():
    # write immediately so you see something on open
    generate_report(live=True)
    while not stop_event.wait(args.interval):
        generate_report(live=True)

# ---------- MAIN ----------
def main():
    print("Starting packet sniffing (Press Ctrl+C to stop)...")
    t = None
    try:
        if args.live:
            t = threading.Thread(target=live_writer_loop, daemon=True)
            t.start()
        sniff(filter="ip", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping sniffing...")
    finally:
        stop_event.set()
        # final, non-refresh report
        generate_report(live=False)
        print(f"\033[92mReport saved to {args.report}\033[0m")
        if args.json:
            print(f"\033[92mMetrics JSON saved to {args.json}\033[0m")

if __name__ == "__main__":
    main()

