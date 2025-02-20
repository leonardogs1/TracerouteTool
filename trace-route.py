from scapy.all import *
from time import perf_counter
import socket
import random
import prettytable

def getOwnIP() -> str:
    """Get the IP address of the current machine."""
    ip = get_if_addr(conf.iface)
    return ip

def traceroute(dest_addr: str, maxHop: int) -> None:
    """Perform a traceroute to a destination address."""
    try:
        destIP = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {dest_addr}")
        return

    myIP = getOwnIP()
    port = random.randint(33434, 33534)  # Port range for traceroute
    ttl = 1
    
    # Initialize Pretty Table
    output = prettytable.PrettyTable()
    output.field_names = ["TTL", "IP Address", "RTT"]
        
    print(f"Performing Traceroute to {dest_addr} [{destIP}] with sourceIP: {myIP} and maxHop: {maxHop}")

    while ttl < maxHop:
        start = perf_counter()  # Start Timer
        
        packet = IP(dst=destIP, ttl=ttl) / UDP(dport=port)
        reply = sr1(packet, verbose=0, timeout=1)

        end = perf_counter()
        rtt = end - start
        
        if reply is None:
            # Case 1: No reply received
            replyIP = "***"
        elif reply.haslayer(ICMP) and reply[ICMP].type == 11:
            # Case 2: Reached but not Destination; Type 11 for Time Exceeded
            replyIP = reply.src
        elif reply.haslayer(IP) and reply[IP].src == destIP:
            # Case 3: Destination Reached; Type 0 for Echo Reply
            output.add_row([ttl, reply.src, f"{rtt * 1000:.4f} ms"])
            break
            
        else:
            # Case 4: Unexpected Packe
            print(f"{ttl} Unexpected packet: {reply.summary()}")  # Handle unexpected packets
            return
        
        output.add_row([ttl, replyIP, f"{rtt * 1000:.4f} ms"])
        ttl += 1
        
    print(output)

if __name__ == "__main__":
    destination = input("Enter destination hostname or IP: ")
    
    if destination == "":
        print("Error: Destination address not provided")
        exit(1)
    
    # Get maximum hops input; if empty, set to 64
    maxHops = input("Enter maximum number of hops (default: 64): ")
    if maxHops.strip() == "":
        maxHops = 64
    else:
        maxHops = int(maxHops)

    if maxHops <= 0:
        print("Invalid number of hops. Setting to default value of 64")
        maxHops = 64

    traceroute(destination, maxHops)
