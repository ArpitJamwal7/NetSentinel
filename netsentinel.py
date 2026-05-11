import nmap
import json
import subprocess
import time
import sys

def get_all_interfaces():
    """System ke saare active network interfaces nikalta hai"""
    interfaces = []
    try:
        cmd = "ip -o -f inet addr show | awk '/scope global/ {print $2, $4}'"
        output = subprocess.check_output(cmd, shell=True).decode().strip().split('\n')
        
        for idx, line in enumerate(output):
            if line:
                iface_name, ip_cidr = line.split()
                interfaces.append({
                    'id': idx + 1,
                    'interface': iface_name,
                    'ip': ip_cidr,
                    'target_cidr': ip_cidr
                })
    except Exception as e:
        print(f"[-] Error detecting interfaces: {e}")
    return interfaces

def run_recon_phase(target_subnet):
    """Phase 1: Network par live devices ko dhoondhna"""
    print(f"\n[*] PHASE 1: Sweeping Subnet: {target_subnet} ...")
    nm = nmap.PortScanner()
    nm.scan(hosts=target_subnet, arguments='-sn -PR')
    
    live_devices = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            live_devices.append({
                'ip_address': host,
                'mac_address': nm[host]['addresses'].get('mac', 'Unknown MAC'),
                'vendor': nm[host]['vendor'].get(nm[host]['addresses'].get('mac', ''), 'Unknown Device'),
                'status': 'Live'
            })
    return live_devices

def run_deep_scan_phase(devices):
    """Phase 2: Live devices par OS aur Service Versions check karna"""
    print(f"\n[*] PHASE 2: Initiating OS & Service Version Scan on {len(devices)} live devices...")
    print("[*] Target Ports: 21,22,23,80,443,445,3389,8080")
    print("[*] (Hold tight! Version detection takes time. Go grab a coffee ☕)\n")
    
    target_ports = '21,22,23,80,443,445,3389,8080'
    ips = [device['ip_address'] for device in devices]
    target_hosts = " ".join(ips)
    
    nm = nmap.PortScanner()
    nm.scan(hosts=target_hosts, ports=target_ports, arguments='-T4 --open -sV -O')
    
    for device in devices:
        ip = device['ip_address']
        device['os_version'] = "Unknown OS"
        device['open_ports'] = []
        
        if ip in nm.all_hosts():
            # OS Extract karna
            if 'osmatch' in nm[ip] and len(nm[ip]['osmatch']) > 0:
                device['os_version'] = nm[ip]['osmatch'][0]['name']
                
            # Ports aur services extract karna
            if 'tcp' in nm[ip]:
                for port in nm[ip]['tcp'].keys():
                    if nm[ip]['tcp'][port]['state'] == 'open':
                        port_data = nm[ip]['tcp'][port]
                        service_name = port_data.get('name', 'unknown')
                        product = port_data.get('product', '')
                        version = port_data.get('version', '')
                        
                        device['open_ports'].append({
                            'port': port,
                            'service_details': f"{service_name} {product} {version}".strip()
                        })
    return devices

def main():
    print("==================================================")
    print("    NETSENTINEL ULTIMATE - ALL-IN-ONE ENGINE      ")
    print("==================================================\n")
    
    print("[*] Detecting Active Network Interfaces...\n")
    networks = get_all_interfaces()
    
    if not networks:
        print("[-] No active networks found. Check your connection.")
        sys.exit()
        
    print(f"{'ID':<5} | {'INTERFACE':<15} | {'ASSIGNED IP & TARGET SUBNET'}")
    print("-" * 60)
    for net in networks:
        print(f"[{net['id']}]   | {net['interface']:<15} | {net['target_cidr']}")
    print("-" * 60)
    
    try:
        choice = int(input("\n[?] Select the Interface ID to scan (e.g., 1 for eth0): "))
        selected_net = next((n for n in networks if n['id'] == choice), None)
        
        if selected_net:
            print(f"\n[+] Interface {selected_net['interface']} selected.")
            subnet = selected_net['target_cidr']
        else:
            print("[-] Invalid selection. Exiting.")
            sys.exit()
    except ValueError:
        print("[-] Please enter a valid number.")
        sys.exit()
        
    start_time = time.time()
    
    # Run Phase 1
    live_devices = run_recon_phase(subnet)
    if not live_devices:
        print("[-] No live devices found on the network. Exiting.")
        sys.exit()
        
    print(f"[+] Recon Complete: Found {len(live_devices)} live devices.")
    
    # Run Phase 2
    final_enriched_data = run_deep_scan_phase(live_devices)
    
    end_time = time.time()
    
    # Save Final Report
    with open('netsentinel_report.json', 'w') as f:
        json.dump(final_enriched_data, f, indent=4)
        
    print("==================================================")
    print(f"[+] Total Execution Time: {round(end_time - start_time, 2)} seconds")
    print(f"[+] Master Report saved to 'netsentinel_report.json'")
    print("==================================================\n")

if __name__ == "__main__":
    # Nmap OS detection requires root
    if sys.platform.startswith('linux'):
        if subprocess.call(['id', '-u']) != 0:
            print("[-] This script requires root privileges for OS detection.")
            print("[*] Please run again using: sudo python3 netsentinel.py")
            sys.exit()
            
    main()
