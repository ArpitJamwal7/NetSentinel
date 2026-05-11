import json
import nmap
import time

def run_port_scan():
    print("==================================================")
    print("     NETSENTINEL - DEEP PORT SCANNER V1.0         ")
    print("==================================================\n")
    
    # 1. Purani file se data read karna
    try:
        with open('scan_results.json', 'r') as f:
            devices = json.load(f)
    except FileNotFoundError:
        print("[-] Error: 'scan_results.json' not found. Run scanner.py first!")
        return

    print(f"[*] Loaded {len(devices)} live devices from Module 1.")
    
    # Target Ports: FTP(21), SSH(22), Telnet(23), HTTP(80, 8080), HTTPS(443), SMB(445), RDP(3389)
    target_ports = '21,22,23,80,443,445,3389,8080'
    
    # Saare 143 IPs ko ek single string mein convert karna taaki scan fast ho
    ips = [device['ip_address'] for device in devices]
    target_hosts = " ".join(ips)
    
    print(f"[*] Initiating Deep Scan on top vulnerable ports ({target_ports})...")
    print("[*] (This might take 2-5 minutes for 143 devices. Please wait...)\n")
    
    nm = nmap.PortScanner()
    start_time = time.time()
    
    # -T4: Fast execution, --open: Sirf open ports dikhaye
    nm.scan(hosts=target_hosts, ports=target_ports, arguments='-T4 --open')
    
    # 2. Scan results ko devices list mein update karna
    for device in devices:
        ip = device['ip_address']
        device['open_ports'] = [] # Default empty list
        
        if ip in nm.all_hosts():
            if 'tcp' in nm[ip]:
                for port in nm[ip]['tcp'].keys():
                    if nm[ip]['tcp'][port]['state'] == 'open':
                        port_info = {
                            'port': port,
                            'service': nm[ip]['tcp'][port]['name']
                        }
                        device['open_ports'].append(port_info)
    
    end_time = time.time()
    
    # 3. Naye Data ko ek Final JSON file mein save karna
    with open('final_scan_results.json', 'w') as f:
        json.dump(devices, f, indent=4)
        
    print("==================================================")
    print(f"[+] Deep Port Scan Complete in {round(end_time - start_time, 2)} seconds!")
    print(f"[+] Enriched data saved to 'final_scan_results.json'")
    print("==================================================\n")
    print("[*] MISSION ACCOMPLISHED! You can now take 'final_scan_results.json' home.")

if __name__ == "__main__":
    run_port_scan()
