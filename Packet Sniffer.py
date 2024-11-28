# Importing the required packages.
import scapy.all
import psutil
from prettytable import PrettyTable
import subprocess
import re
import time
from colorama import Fore
from colorama import Style
from scapy.layers.inet import IP, TCP, UDP, ICMP


def display_logo():
    logo = f"""
{Fore.RED}{Style.BRIGHT}    ____            _        _     ____        _  __  __           
   |  _ \ __ _  ___| | _____| |_  / ___| _ __ (_)/ _|/ _| ___ _ __ 
   | |_) / _` |/ __| |/ / _ \ __| \___ \| '_ \| | |_| |_ / _ \ '__|
   |  __/ (_| | (__|   <  __/ |_   ___) | | | | |  _|  _|  __/ |   
   |_|   \__,_|\___|_|\_\___|\__| |____/|_| |_|_|_| |_|  \___|_|   

|----------------------------------------------------------------------------|
| Created By: Sayantan Saha                                                  |
| Checkout my LinkedIn: https://www.linkedin.com/in/mastersayantan/          |
| Lookup at my GitHub Account: https://github.com/MasterSayantan             |
|----------------------------------------------------------------------------|
{Style.RESET_ALL}
    """
    print(logo)


def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        return re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(output)).group(0)
    except:
        pass


def get_current_ip(interface):
    output = subprocess.check_output(["ifconfig", interface])
    pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    output1 = output.decode()
    ip = pattern.search(output1)[0]
    return ip


def ip_table():
   
    addrs = psutil.net_if_addrs()
    t = PrettyTable(
        [f"{Fore.GREEN}Interface", "Mac Address", f"IP Address{Style.RESET_ALL}"]
    )
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.MAGENTA}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.MAGENTA}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)


def sniff(interface):
    scapy.all.sniff(iface=interface, prn=packet_callback, store=False)


def packet_callback(packet):
    
    packet_details = f"{Fore.YELLOW}Packet Details:{Style.RESET_ALL}\n"

   
    if IP in packet:
        packet_details += f"{Fore.GREEN}IP Layer:{Style.RESET_ALL}\n"
        packet_details += (
            f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}\n"
        )
        packet_details += f"ID: {packet[IP].id} ; Version: {packet[IP].version} ; Length: {packet[IP].len} ; Flags: {packet[IP].flags}\n"
        packet_details += f"Protocol: {packet[IP].proto} ; TTL: {packet[IP].ttl} ; Checksum: {packet[IP].chksum}\n"

    
    if TCP in packet:
        packet_details += f"{Fore.RED}TCP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}\n"
        packet_details += f"Sequence Number: {packet[TCP].seq} ; Acknowledgment Number: {packet[TCP].ack}\n"
        packet_details += (
            f"Window: {packet[TCP].window} ; Checksum: {packet[TCP].chksum}\n"
        )
        packet_details += (
            f"Flags: {packet[TCP].flags} ; Options: {packet[TCP].options}\n"
        )

    
    if UDP in packet:
        packet_details += f"{Fore.RED}UDP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[UDP].sport}\n"
        packet_details += f"Destination Port: {packet[UDP].dport}\n"

    
    if ICMP in packet:
        packet_details += f"{Fore.RED}ICMP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Type: {packet[ICMP].type}\n"
        packet_details += f"Code: {packet[ICMP].code}\n"

    
    print(packet_details)


def main():
    display_logo()
    print(f"{Fore.YELLOW}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(
        f"{Fore.RED}[***] Please Start Arp Spoofer Before Using this Module [***]{Style.RESET_ALL}"
    )
    try:
        ip_table()
        interface = input("[*] Please enter the interface name: ")
        print(get_current_ip(interface))
        print(get_current_mac(interface))
        print("[*] Sniffing Packets...")
        sniff(interface)
        print(f"{Fore.RED}\n[*] Interrupt...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Stopping the Sniffer...{Style.RESET_ALL}")
        time.sleep(3)

if __name__ == "__main__":
    main()

