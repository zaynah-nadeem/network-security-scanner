from flask import Flask, render_template, request, jsonify
import nmap
import ipaddress
import socket
import re

app = Flask(__name__)


MAX_ADDRESSES = 256
MAX_PORTS = 2001
MAX_UDP_PORTS = 100

SCAN_OPTIONS = {
    "connect": "-sT -sV",
    "syn": "-sS -sV",
    "udp": "-sU -sV",
}

RISKY_PORTS = {
    21: ("High", "FTP sends usernames and passwords in plain text."),
    23: ("High", "Telnet is unencrypted. Use SSH instead."),
    25: ("Medium", "SMTP can be abused for spam if misconfigured."),
    53: ("Low", "DNS should not be open to untrusted networks."),
    80: ("Low", "HTTP is unencrypted. Prefer HTTPS."),
    110: ("Medium", "POP3 sends passwords in plain text."),
    135: ("High", "Windows RPC is a common attack target."),
    139: ("High", "NetBIOS can leak shared files and system info."),
    143: ("Medium", "IMAP without TLS sends passwords in plain text."),
    161: ("High", "SNMP with default settings leaks device info."),
    445: ("High", "SMB is a common ransomware target (e.g. WannaCry)."),
    1433: ("High", "MSSQL database should not be exposed."),
    3306: ("High", "MySQL database should not be exposed."),
    3389: ("High", "Remote Desktop (RDP) is often brute-forced."),
    5432: ("High", "PostgreSQL database should not be exposed."),
    5900: ("High", "VNC often has a weak or no password."),
    6379: ("High", "Redis often has no authentication."),
    8080: ("Low", "Alternate HTTP port, often used by admin panels."),
}


def is_local(address):
    return address.is_private or address.is_loopback or address.is_link_local


def validate_target(target):
    target = target.strip()

    if not target:
        raise ValueError("Please enter an IP address, network or hostname.")

    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise ValueError("Invalid network address.")

        if network.num_addresses > MAX_ADDRESSES:
            raise ValueError("Network too large. Maximum is /24 (256 addresses).")

        if not is_local(network):
            raise ValueError("Only local and private network targets are allowed.")

        return str(network)

    try:
        addresses = [ipaddress.ip_address(target)]

    except ValueError:
        try:
            infos = socket.getaddrinfo(target, None)
        except socket.gaierror:
            raise ValueError("Hostname could not be resolved.")

        addresses = {ipaddress.ip_address(info[4][0]) for info in infos}

    for address in addresses:
        if not is_local(address):
            raise ValueError("Only local and private network targets are allowed.")

    return target


def validate_ports(port_text, scan_type):
    port_text = port_text.strip()

    if not re.fullmatch(r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*", port_text):
        raise ValueError("Invalid port format. Use e.g. 22,80,443 or 1-1024.")

    total = 0

    for part in port_text.split(","):
        start, end = port_range(part)

        if not 1 <= start <= end <= 65535:
            raise ValueError("Ports must be between 1 and 65535.")

        total += end - start + 1

    limit = MAX_UDP_PORTS if scan_type == "udp" else MAX_PORTS

    if total > limit:
        raise ValueError(f"Maximum {limit} ports for this scan type.")

    return port_text


def port_range(text):
    if "-" in text:
        start, end = map(int, text.split("-"))
    else:
        start = end = int(text)
    return start, end


def get_risk(port, state):
    if "open" not in state:
        return "None", "Port is not open."

    if port in RISKY_PORTS:
        return RISKY_PORTS[port]

    return "Low", "Open port. Close it if the service is not needed."


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}

    try:
        scan_type = data.get("scan_type", "connect")

        if scan_type not in SCAN_OPTIONS:
            raise ValueError("Invalid scan type.")

        target = validate_target(str(data.get("target", "")))
        ports = validate_ports(str(data.get("ports", "1-1024")), scan_type)

        arguments = SCAN_OPTIONS[scan_type] + " -T4"

        if "/" not in target:
            arguments += " -Pn"

        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, ports=ports, arguments=arguments)

    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    except nmap.PortScannerError as e:
        error = str(e)

        if "root privileges" in error.lower():
            error = ("TCP SYN and UDP scans need administrator/root rights. "
                     "Run the app as admin (sudo on Linux/macOS) or use TCP Connect.")

        return jsonify({"success": False, "error": error}), 500

    results = []
    hosts = scanner.all_hosts()

    for host in hosts:
        for protocol in scanner[host].all_protocols():
            for port, details in sorted(scanner[host][protocol].items()):

                state = details.get("state", "unknown")
                risk, reason = get_risk(port, state)

                results.append({
                    "ip": host,
                    "port": port,
                    "protocol": protocol.upper(),
                    "service": details.get("name") or "unknown",
                    "product": details.get("product", ""),
                    "version": details.get("version", ""),
                    "status": state,
                    "risk": risk,
                    "reason": reason,
                })

    if not hosts:
        message = "No hosts responded. The target may be offline or blocking scans."
    else:
        open_ports = sum(1 for r in results if "open" in r["status"])
        message = f"Scan complete: {len(hosts)} host(s) up, {open_ports} open port(s) found."

    return jsonify({"success": True, "results": results, "message": message})


def parse_rule(rule, number):
    action = str(rule.get("action", "")).upper()
    ip = str(rule.get("ip", "")).strip().lower() or "any"
    port = str(rule.get("port", "")).strip().lower() or "any"
    protocol = str(rule.get("protocol", "any")).lower()

    if action not in ("ALLOW", "DENY"):
        raise ValueError(f"Rule {number}: action must be ALLOW or DENY.")

    if protocol not in ("any", "tcp", "udp"):
        raise ValueError(f"Rule {number}: invalid protocol.")

    if ip != "any":
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            raise ValueError(f"Rule {number}: invalid IP address or network.")

    if port != "any":
        if not re.fullmatch(r"\d{1,5}(-\d{1,5})?", port):
            raise ValueError(f"Rule {number}: port must be 'any', 80 or 20-25.")

        start, end = port_range(port)

        if not 1 <= start <= end <= 65535:
            raise ValueError(f"Rule {number}: invalid port range.")

    return {"action": action, "ip": ip, "port": port, "protocol": protocol}


def rule_matches(rule, dst_ip, dst_port, protocol):
    ip_ok = (
        rule["ip"] == "any"
        or dst_ip in ipaddress.ip_network(rule["ip"], strict=False)
    )

    if rule["port"] == "any":
        port_ok = True
    else:
        start, end = port_range(rule["port"])
        port_ok = start <= dst_port <= end

    protocol_ok = rule["protocol"] in ("any", protocol)

    return ip_ok and port_ok and protocol_ok


def describe_rule(rule):
    return f"{rule['action']} {rule['protocol'].upper()} to {rule['ip']} port {rule['port']}"


@app.route("/simulate", methods=["POST"])
def simulate():
    data = request.get_json(silent=True) or {}

    try:
        traffic = data.get("traffic") or {}

        try:
            dst_ip = ipaddress.ip_address(str(traffic.get("ip", "")).strip())
        except ValueError:
            raise ValueError("Invalid destination IP address.")

        port_text = str(traffic.get("port", "")).strip()

        if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            raise ValueError("Invalid destination port.")

        dst_port = int(port_text)
        protocol = str(traffic.get("protocol", "")).lower()

        if protocol not in ("tcp", "udp"):
            raise ValueError("Invalid protocol.")

        default_policy = str(data.get("default_policy", "deny")).upper()

        if default_policy not in ("ALLOW", "DENY"):
            raise ValueError("Default policy must be ALLOW or DENY.")

        rules = [
            parse_rule(rule, number)
            for number, rule in enumerate(data.get("rules") or [], start=1)
        ]

    except (ValueError, AttributeError) as e:
        return jsonify({"success": False, "error": str(e)}), 400

    decision = default_policy
    matched_rule = f"No rule matched, so the default policy ({default_policy}) was used."
    used_default = True
    trace = []

    for number, rule in enumerate(rules, start=1):

        if not used_default:
            status = "skipped"

        elif rule_matches(rule, dst_ip, dst_port, protocol):
            status = "matched"
            used_default = False
            decision = rule["action"]
            matched_rule = f"Rule {number} matched: {describe_rule(rule)}."

        else:
            status = "no match"

        trace.append({
            "rule": number,
            "action": rule["action"],
            "description": describe_rule(rule),
            "status": status,
        })

    return jsonify({
        "success": True,
        "decision": decision,
        "matched_rule": matched_rule,
        "default_policy": default_policy,
        "used_default": used_default,
        "trace": trace,
        "explanation": "Traffic is allowed." if decision == "ALLOW" else "Traffic is blocked.",
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)