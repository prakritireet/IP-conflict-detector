from flask import Flask, render_template, request
from scapy.all import ARP, Ether, srp
from collections import defaultdict

app = Flask(__name__)

def scan_network(network):
    """Scan the given network and return IP-MAC mappings."""
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices


def detect_conflicts(devices):
    """Check for IP or MAC address conflicts."""
    ip_to_mac = defaultdict(list)
    mac_to_ip = defaultdict(list)

    for d in devices:
        ip_to_mac[d['ip']].append(d['mac'])
        mac_to_ip[d['mac']].append(d['ip'])

    conflicts = []
    for ip, macs in ip_to_mac.items():
        if len(set(macs)) > 1:
            conflicts.append(f"⚠️ IP Conflict: {ip} mapped to multiple MACs: {macs}")
    for mac, ips in mac_to_ip.items():
        if len(set(ips)) > 1:
            conflicts.append(f"ℹ️ Device {mac} responding to multiple IPs: {ips}")

    return conflicts


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        network = request.form.get('network')
        if not network:
            return render_template('index.html', error="Please enter a valid IP or subnet.")

        devices = scan_network(network)
        conflicts = detect_conflicts(devices)

        return render_template('index.html', devices=devices, conflicts=conflicts, network=network)
    
    return render_template('index.html')


if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=10000)


