from scapy.all import *
from scapy.layers.http import HTTPRequest # Load HTTP layer
import json

def process_packet(packet):
    """Har capture hue packet ko analyze karta hai"""
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip_src = packet[IP].src
        method = packet[HTTPRequest].Method.decode()
        
        print(f"\n[!] HTTP Request Detected!")
        print(f"    Source IP: {ip_src}")
        print(f"    Method: {method}")
        print(f"    URL: {url}")

        # Agar POST request hai, toh password/data leak check karo
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode(errors='ignore')
            keywords = ["username", "user", "password", "pass", "login", "email"]
            for keyword in keywords:
                if keyword in load.lower():
                    print(f"    [CRITICAL] Possible Data Leak: {load}")
                    
                    # Dashboard ke liye data save karna
                    leak_info = {
                        "type": "Data Leak",
                        "source": ip_src,
                        "data": load,
                        "url": url
                    }
                    with open('live_leaks.json', 'a') as f:
                        json.dump(leak_info, f)
                        f.write('\n')

def start_sniffing(interface):
    print(f"[*] Starting PacketPeek on interface: {interface}")
    print("[*] Monitoring for unencrypted HTTP traffic... Press Ctrl+C to stop.")
    # filter="port 80" taaki sirf web traffic scan ho aur system slow na ho
    sniff(iface=interface, prn=process_packet, filter="port 80", store=0)

if __name__ == "__main__":
    # Apne interface ka naam yahan likhein (mostly eth0 ya wlan0)
    # Aapne pichli script mein eth0 use kiya tha
    try:
        start_sniffing("eth0")
    except KeyboardInterrupt:
        print("\n[-] Stopping PacketPeek...")
