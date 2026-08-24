from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
#color codes for terminal
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"
#pacekts  Counters for summary
tcp_count = 0
udp_count = 0
other_count = 0
#Log file (appends to existing file)
log_file = open("sniffer_log.txt", "a")
def analyze_packet(packet):
    global tcp_count, udp_count, other_count
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        timestamp = datetime.now().strftime("%H:%M:%S")
        #- - - TCP packets - - - -
        if TCP in packet:
           tcp_count +=1
           protocol_name = "TCP"
           src_port = packet[TCP].sport
           dst_port = packet[TCP].dport
           line = f"[{timestamp}] [TCP] {src_ip}:{src_port} - > {dst_ip}:{dst_port}"
           print(GREEN + line + RESET)
           log_file.write(line + "\n")
           if Raw in packets:
                payload = packet[Raw].load
                payload_line = f"    payload: {payload}"
                print(payload_line)
                log_file.write(payload_line + "\n")
        # - - - - UDP - - - -
        elif UDP in packet:
           udp_count +=1
           protocol_name = "UDP"
           src_port = packet[UDP].sport
           dst_port = packet[UDP].dport
           line = f"[{timestamp} [UDP] {src_ip}:{src_port} - > {dst_ip}:{dst_port}"
           print(BLUE + line + RESET)
           log_file.write(line + "\n")
           if Raw in packet:
               payload = packet[Raw].load
               payload_line = f"    payload: {payload}"
               print(payload_line)
               log_file.write(payload_line + "\n")
        # - - - - other protocols (ICMP, etc.) - - - -
        else:
           other_count +=1
           line = f"[{timestamp}] [OTHER] {src_ip} - > {dst_ip} (protocol: {proto})"
           print(YELLOW + line + RESET)
           log_file.write(line + "\n")
print("Starting network sniffer... press Ctrl+C to stop.\n")
try:
   # count=20 captures 20 packets and stops: remove count= to run until Ctrl+C
   sniff(prn=analyze_packet, filter="ip", store=False, count=20)
except keyboardInterrupt:
   pass
# - - - - Summary - - - -
print("\n- - - Summary - - -")
print(f"TCP packets: {tcp_count}")
print(f"UDP packets: {udp_count}")
print(f"Other packets: {other_count}")
print(f"Total: {tcp_count + udp_count + other_count}")
log_file.close()
