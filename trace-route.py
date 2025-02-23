from scapy.all import *
from time import perf_counter
import socket
import random
import prettytable

def getOwnIP() -> str:
    """Get the IP address of the current machine"""
    try:
        return get_if_addr(conf.iface)
    except Exception:
        return ""

def getCanonicalName(ip: str) -> str:
    """Get the canonical name of a given IP address"""
    try:
        host_info = socket.gethostbyaddr(ip)
        host = host_info[0]
    except socket.herror:
        host = ""
    return host


def traceroute(dest_ip: str, max_hop: int) -> None:
    """Perform a traceroute to a destination address"""

    my_ip = getOwnIP()
    port = random.randint(33434, 33534)  # Port range for traceroute
    ttl = 1

    # Initialize Pretty Table
    output_table = prettytable.PrettyTable()
    output_table.field_names = ["TTL", "IP Address", "RTT", "Host"]
        
    print(f"Performing Traceroute to [{dest_ip}] with sourceIP: {my_ip} and maxHop: {max_hop}")

    reply_ip = ""
    while reply_ip != dest_ip and ttl <= max_hop:
        start = perf_counter() 
        host = ""

        # Send packet UDP packet with increasing TTL
        packet = IP(dst=dest_ip, ttl=ttl) / UDP(dport=port)
        reply = sr1(packet, verbose=0, timeout=1)

        end = perf_counter()
        rtt = end - start

        if reply:
            if reply.haslayer(ICMP):
                 # Case 1 & 2: Time Exceeded or Destination Unreachable
                if reply[ICMP].type in [11, 3]:
                    reply_ip = reply.src
                    host = getCanonicalName(reply_ip)
                else:
                    print(f"{ttl} ICMP type: {reply[ICMP].type}")
                    return
            else:
                print(f"{ttl} Unexpected packet: {reply.summary()}")
                return
        else:
            # Case 3: No reply received
            reply_ip = "***"
        
        output_table.add_row([ttl, reply_ip, f"{rtt:.4f} ms", host])  
        ttl += 1
        
    
    print(output_table)
        
if __name__ == "__main__":    
    try:
        destination = input("Enter destination hostname or IP: ")
        dest_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {destination}")
        exit(1)
    
    # Get maximum hops input; if empty or invalid , set to 64
    max_hops = input("Enter maximum number of hops (default: 64): ")
    if max_hops.strip() == "":
        max_hops = 64
    else:
        max_hops = int(max_hops)

    if max_hops <= 0:
        print("Invalid number of hops. Setting to default value of 64")
        max_hops = 64

    traceroute(dest_ip, max_hops)
