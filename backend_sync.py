import requests
import json
import time

# ==========================================
# APNA FIREBASE DATABASE URL YAHAN DAALEIN
# (End mein '.json' lagana zaroori hai)
# Example: "https://netsentinel-xyz-default-rtdb.firebaseio.com/autorecon_devices.json"
# ==========================================
FIREBASE_URL = "https://YOUR_PROJECT_ID-default-rtdb.firebaseio.com/autorecon_devices.json"

def send_data_to_firebase(device_id, ip, mac, os_name, ports):
    """Network scan ke data ko live Firebase par bhejta hai"""
    
    # Data ka structure
    payload = {
        device_id: {
            "ip_address": ip,
            "mac_address": mac,
            "os_version": os_name,
            "open_ports": ports
        }
    }
    
    try:
        # PATCH request se naya data add hota hai (purana delete nahi hota)
        response = requests.patch(https://netsentinel-5ef8d-default-rtdb.firebaseio.com/autorecon_devices.json, json=payload)
        
        if response.status_code == 200:
            print(f"[SUCCESS] Data sent for {ip} -> Dashboard updated live!")
        else:
            print(f"[ERROR] Failed to send data: {response.text}")
            
    except Exception as e:
        print(f"[!] Connection Error: {e}")

# --- Test Data (Jab Kali par chalayenge toh yahan Nmap ka data aayega) ---
if __name__ == "__main__":
    print("[*] Simulating AutoRecon Scan...")
    time.sleep(2) # Fake scan delay
    
    # Ek fake device bhej kar test karte hain
    test_ports = [
        {"port": 22, "service_details": "ssh"},
        {"port": 80, "service_details": "http Apache"}
    ]
    
    send_data_to_firebase("device_02", "192.168.1.50", "00:1A:2B:3C:4D:5E", "Kali Linux (Bare Metal)", test_ports)