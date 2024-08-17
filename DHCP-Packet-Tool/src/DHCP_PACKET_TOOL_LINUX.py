from scapy.all import sniff, Ether, IP, DHCP # type: ignore
from term_colors import *
import netifaces


def packet_callback(packet):
    # Check if the packet has a DHCP layer
    if packet.haslayer(DHCP) and packet[DHCP].options[0][1] == 1:  # DHCPDISCOVER has option 0 with value 1
        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        src_mac = packet[Ether].src
        print(f"DHCPDISCOVER Packet Captured!")
        print(f"Source IP: {src_ip}")
        prCyan(f"Source MAC: {src_mac}")

def get_interface():
    interface_list = netifaces.interfaces()
    print(f"{len(interface_list)} interfaces are up")
    if len(interface_list) < 1:
        print ("no interfaces are up")
        quit()
    else:
        print( "Please Enter the Index of the interface you want to listen to DHCP request on.")
        print("index \t| interface")
        for index,interface in enumerate(interface_list):
            print(index, "\t|", interface)
        choice = int(input())
        activeInt = interface_list[choice]
        return activeInt 

def main():
    prYellow("This Script was written on Ubuntu 24.04 LTS (Noble Numbat)")
    interface = get_interface()
    # Sniff DHCP packets on the specified interface
    print(f"Starting packet sniffing for DHCPDISCOVER packets on {interface}...")
    sniff(prn=packet_callback, filter="udp and (port 67 or 68)", iface=interface, store=0)

if __name__ == "__main__":
    main()


