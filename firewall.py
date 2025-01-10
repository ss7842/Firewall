import configparser
from scapy.all import sniff, IP, TCP, UDP

# Load rules from ini files
def load_rules(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)
    rules = {}
    for section in config.sections():
        rules[section] = dict(config.items(section))
    return rules

# Check packet rules
def check_inbound(packet, rules):
    src_ip = packet[IP].src
    src_port = packet[IP].sport
    if 'ALLOW' in rules and src_ip in rules['ALLOW'] and rules['ALLOW'][src_ip] == str(src_port):
        return "ACCEPT"
    return "REJECT"

def check_outbound(packet, rules):
    dst_ip = packet[IP].dst
    dst_port = packet[IP].dport
    if 'ALLOW' in rules and dst_ip in rules['ALLOW'] and rules['ALLOW'][dst_ip] == str(dst_port):
        return "ACCEPT"
    return "REJECT"

def process_packet(packet):
    if IP in packet:
        if packet[IP].dst == "your_server_ip":  # Replace with your server's IP
            action = check_inbound(packet, inbound_rules)
        else:
            action = check_outbound(packet, outbound_rules)
        
        if action == "ACCEPT":
            print(f"Packet allowed: {packet.summary()}")
        else:
            print(f"Packet REJECTED: {packet.summary()}")

# Load rules
inbound_rules = load_rules("inbound_rules.ini")
outbound_rules = load_rules("outbound_rules.ini")

# Start sniffing
sniff(prn=process_packet, filter="ip", store=0)


