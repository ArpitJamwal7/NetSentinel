import nmap
import json
import subprocess
import time

def get_all_interfaces():
    """Kali Linux ke saare active networks aur unke subnets nikalta hai"""
    interfaces = []
    try:
        cmd = "ip -o -f inet addr show | awk '/scope global/ {print $2, $4}'"
        output = subprocess.check_output(cmd, shell=True).decode().strip().split('\n')
        
        for idx, line in enumerate(output):
            if line:
                iface_name, ip_cidr = line.split()
                # Subnet calculate karna (e.g., 172.16.26.218/21 -> 172.16.24.0/21)
                ip_base = ip_cidr.split('/')[0].split('.')
                # Quick hack for basic subnet display, nmap handles standard CIDR inputs well
                subnet = f"{ip_base[0]}.{ip_base[1]}.{ip_base[2]}.0/24" 
                # Note: Nmap can directly take the CIDR like 172.16.26.218/21 
                # So we will pass the actual CIDR notation for precise enterprise scanning
                
                interfaces.append({
                    'id': idx + 1,
                    'interface': iface_name,
                    'ip': ip_cidr,
                    'target_cidr': ip_cidr  # Using exact CIDR for large networks
                })
    except Exception as e:
        print(f"[-] Error detecting interfaces: {e}")
    return interfaces

def run_network_scan(target_subnet):
    print(f"\n[*] Sweeping Subnet: {target_subnet} ... Please wait.")
    print("[*] (Large networks may take 30-60 seconds to respond)\n")
    
    nm = nmap.PortScanner()
    # -sn: Ping Scan, -PR: ARP Ping (highly effective on local subnets)
    nm.scan(hosts=target_subnet, arguments='-sn -PR')
    
    live_devices = []
    
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            device_info = {
                'ip_address': host,
                'mac_address': nm[host]['addresses'].get('mac', 'Unknown MAC'),
                'vendor': nm[host]['vendor'].get(nm[host]['addresses'].get('mac', ''), 'Unknown Device'),
                'status': 'Live'
            }
            live_devices.append(device_info)
            
    return live_devices

if __name__ == "__main__":
    print("==================================================")
    print("     NETSENTINEL - ADVANCED RECON ENGINE V2.0     ")
    print("==================================================\n")
    
    print("[*] Detecting Active Network Interfaces...\n")
    networks = get_all_interfaces()
    
    if not networks:
        print("[-] No active networks found. Check your connection.")
        exit()
        
    print(f"{'ID':<5} | {'INTERFACE':<15} | {'ASSIGNED IP & TARGET SUBNET'}")
    print("-" * 60)
    for net in networks:
        print(f"[{net['id']}]   | {net['interface']:<15} | {net['target_cidr']}")
    print("-" * 60)
    
    try:
        choice = int(input("\n[?] Select the Interface ID to scan (e.g., 2 for eth0): "))
        selected_net = next((n for n in networks if n['id'] == choice), None)
        
        if selected_net:
            print(f"\n[+] Interface {selected_net['interface']} selected.")
            # Nmap can scan the whole block by taking the IP/CIDR directly
            subnet = selected_net['target_cidr'] 
        else:
            print("[-] Invalid selection. Exiting.")
            exit()
    except ValueError:
        print("[-] Please enter a valid number.")
        exit()
        
    start_time = time.time()
    scanned_data = run_network_scan(subnet)
    end_time = time.time()
    
    json_output = json.dumps(scanned_data, indent=4)
    
    # Save the output silently instead of printing it all
    with open('scan_results.json', 'w') as f:
        f.write(json_output)
        
    print("==================================================")
    print(f"[+] Scan Complete in {round(end_time - start_time, 2)} seconds!")
    print(f"[+] Data successfully saved to 'scan_results.json'")
    print(f"🚀 TOTAL LIVE DEVICES DETECTED: {len(scanned_data)}")
    print("==================================================\n")
