# NetSentinel V4.2 - Enhanced Enterprise Scanner
import nmap
import requests
import time
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

# ==========================================
# 1. FIREBASE CONFIG
# ==========================================
FIREBASE_URL = "https://netsentinel-5ef8d-default-rtdb.firebaseio.com"
DEVICES_NODE = f"{FIREBASE_URL}/devices"
ALERTS_NODE = f"{FIREBASE_URL}/alerts"

# ==========================================
# 2. SAFE PRIVATE SUBNET DISCOVERY
# ==========================================
def get_all_private_subnets():

    print("[*] Loading enterprise subnet targets...")

    return [
        "192.16.0.0/12",
        "192.168.0.0/16",
        "10.0.0.0/8"
    ]

# ==========================================
# 3. CLEAN FIREBASE NODES
# ==========================================
def clear_portal():

    print("[*] Cleaning old dashboard data...")

    try:
        requests.delete(f"{DEVICES_NODE}.json", timeout=5)
        requests.delete(f"{ALERTS_NODE}.json", timeout=5)

        print("[✔] Dashboard Cleared")

    except Exception:
        pass

# ==========================================
# 4. DEVICE NAME DETECTION
# ==========================================
def get_device_name(ip, hostdata):

    device_name = "Unknown"

    # Nmap Hostname
    try:

        if (
            'hostnames' in hostdata and
            len(hostdata['hostnames']) > 0
        ):

            hostname_data = hostdata['hostnames'][0]

            if hostname_data.get('name'):
                device_name = hostname_data['name']

    except:
        pass

    # Reverse DNS
    if device_name == "Unknown":

        try:
            device_name = socket.gethostbyaddr(ip)[0]
        except:
            pass

    # SMB Detection
    if device_name == "Unknown":

        try:

            smb_result = subprocess.check_output(
                ["netexec", "smb", ip],
                stderr=subprocess.DEVNULL,
                timeout=8
            ).decode()

            if "(name:" in smb_result:
                device_name = smb_result.split("(name:")[1].split(")")[0]

        except:
            pass

    return device_name

# ==========================================
# 5. DEVICE TYPE DETECTION
# ==========================================
def detect_device_type(os_name, open_ports):

    os_lower = os_name.lower()

    ports = [p['port'] for p in open_ports]

    if "windows" in os_lower:
        return "Windows PC"

    elif "android" in os_lower:
        return "Android Device"

    elif "ios" in os_lower:
        return "iPhone / iPad"

    elif "macos" in os_lower or "darwin" in os_lower:
        return "Mac Device"

    elif "openwrt" in os_lower:
        return "Router"

    elif 554 in ports:
        return "CCTV Camera"

    elif 9100 in ports:
        return "Printer"

    elif "linux" in os_lower:
        return "Linux Device"

    return "Unknown"

# ==========================================
# 6. RISK ENGINE
# ==========================================
def calculate_risk(open_ports, vuln_alerts):

    risk_score = 0

    risky_ports = {
        21: 20,
        23: 40,
        445: 25,
        3389: 25,
        5900: 20
    }

    for port_data in open_ports:

        port = port_data['port']

        if port in risky_ports:
            risk_score += risky_ports[port]

    risk_score += len(vuln_alerts) * 10

    if risk_score >= 60:
        return risk_score, "Critical Risk", "Compromised"

    elif risk_score >= 30:
        return risk_score, "High Risk", "Compromised"

    elif risk_score > 0:
        return risk_score, "Med Risk", "Warning"

    return risk_score, "Low Risk", "Compliant"

# ==========================================
# 7. DEEP SCAN + FIREBASE PUSH
# ==========================================
def deep_scan_and_push(ip):

    nm = nmap.PortScanner()

    try:

        nm.scan(
            hosts=ip,
            arguments='-O -sV -F -T4 --max-retries 1'
        )

        if ip not in nm.all_hosts():
            return

        hostdata = nm[ip]

        # --------------------------------------
        # MAC + Vendor
        # --------------------------------------
        mac = hostdata['addresses'].get('mac', 'Unknown')

        vendor = hostdata.get(
            'vendor',
            {}
        ).get(mac, 'Unknown')

        # --------------------------------------
        # OS Detection
        # --------------------------------------
        os_name = "Unknown"

        if (
            hostdata.get('osmatch') and
            len(hostdata['osmatch']) > 0
        ):

            os_name = hostdata['osmatch'][0]['name']

        # --------------------------------------
        # Device Name
        # --------------------------------------
        device_name = get_device_name(ip, hostdata)

        # --------------------------------------
        # Open Ports
        # --------------------------------------
        open_ports = []

        vuln_alerts = []

        if 'tcp' in hostdata:

            for port, pdata in hostdata['tcp'].items():

                if pdata['state'] == 'open':

                    open_ports.append({
                        "port": port,
                        "service": pdata.get('name', 'unknown')
                    })

        # --------------------------------------
        # Device Type
        # --------------------------------------
        device_type = detect_device_type(
            os_name,
            open_ports
        )

        # --------------------------------------
        # Risk Engine
        # --------------------------------------
        risk_score, risk_level, status_flag = calculate_risk(
            open_ports,
            vuln_alerts
        )

        # --------------------------------------
        # Device ID
        # --------------------------------------
        device_id = (
            mac.replace(":", "_")
            if mac != "Unknown"
            else ip.replace(".", "_")
        )

        # --------------------------------------
        # Payload
        # --------------------------------------
        payload = {

            "device_name": device_name,
            "device_type": device_type,
            "ip_address": ip,
            "mac_address": mac,
            "vendor": vendor,
            "os_version": os_name,
            "open_ports": open_ports,
            "vulnerabilities": vuln_alerts,
            "status_flag": status_flag,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "online": True,
            "last_seen": time.strftime("%H:%M:%S"),
            "scan_timestamp": int(time.time())
        }

        # --------------------------------------
        # Firebase Push
        # --------------------------------------
        requests.put(
            f"{DEVICES_NODE}/{device_id}.json",
            json=payload,
            timeout=5
        )

        # --------------------------------------
        # Alert Push
        # --------------------------------------
        if risk_score > 0:

            alert_payload = {
                "device_name": device_name,
                "ip_address": ip,
                "risk_level": risk_level,
                "timestamp": int(time.time())
            }

            requests.post(
                f"{ALERTS_NODE}.json",
                json=alert_payload,
                timeout=3
            )

        # --------------------------------------
        # Terminal Output
        # --------------------------------------
        if risk_score > 0:

            print(
                f"[🚨 ALERT] "
                f"{device_name} | "
                f"{device_type} | "
                f"{ip} | "
                f"{risk_level}"
            )

        else:

            print(
                f"[✔ SAFE] "
                f"{device_name} | "
                f"{device_type} | "
                f"{ip}"
            )

    except Exception as e:

        print(f"[!] Scan Error on {ip}: {str(e)}")

# ==========================================
# 8. DISCOVERY ENGINE
# ==========================================
def radar():

    subnets = get_all_private_subnets()

    nm_disc = nmap.PortScanner()

    with ThreadPoolExecutor(max_workers=30) as executor:

        for subnet in subnets:

            print(f"\n[*] Scanning subnet: {subnet}")

            try:

                nm_disc.scan(
                    hosts=subnet,
                    arguments='-sn -T4 --max-retries 1'
                )

                for host in nm_disc.all_hosts():

                    if nm_disc[host].state() == 'up':

                        executor.submit(
                            deep_scan_and_push,
                            host
                        )

            except Exception as e:

                print(
                    f"[!] Subnet scan failed: {str(e)}"
                )

# ==========================================
# 9. MAIN EXECUTION
# ==========================================
if __name__ == "__main__":

    print("====================================================")
    print(" NETSENTINEL V4.2 - ENHANCED ENTERPRISE SCANNER")
    print("====================================================")

    clear_portal()

    try:

        while True:

            radar()

            print("\n[*] Scan cycle complete. Waiting 30s...")

            time.sleep(30)

    except KeyboardInterrupt:

        print("\n[!] Scanner stopped.")
