#!/usr/bin/env python3
"""
NetScan - Détection des hôtes actifs et de leurs ports ouverts
Auteur : Arno Teixeira
Commentaire : Petit outil de scan réseau pour apprentissage.
"""

from scapy.all import ARP, Ether, srp
import socket
import json
import os

# ----------- CONFIGURATION -----------
IP_RANGE = "192.168.1.0/24"  # Plage réseau à scanner
COMMON_PORTS = [22, 80, 443, 8080]  # Ports TCP à tester
OUTPUT_FILE = "output/results.json"
# --------------------------------------

def scan_hosts(ip_range):
    """Scanne une plage réseau pour trouver les hôtes actifs."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for _, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def scan_ports(ip, ports):
    """Teste les ports TCP ouverts sur une IP donnée."""
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except socket.error:
            pass
        finally:
            s.close()
    return open_ports

def save_results(devices, file_path):
    """Enregistre les résultats au format JSON."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        json.dump(devices, f, indent=4)
    print(f"[+] Résultats sauvegardés dans {file_path}")

if __name__ == "__main__":
    print("[*] Scan du réseau en cours...")
    devices = scan_hosts(IP_RANGE)

    print(f"[+] {len(devices)} hôte(s) trouvé(s) :")
    for device in devices:
        open_ports = scan_ports(device['ip'], COMMON_PORTS)
        device['open_ports'] = open_ports
        print(f" - {device['ip']} ({device['mac']}) → Ports ouverts: {open_ports if open_ports else 'Aucun'}")

    save_results(devices, OUTPUT_FILE)
    print("[✓] Scan terminé !")
