from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import pandas as pd
from collections import defaultdict

PCAP = "network_attacks.pcap"
WINDOW = 15  # koll 15 paquets = satr

# El IPs mta3 el réseau
ATTACKER = "192.168.56.104"
VICTIMS = ["192.168.56.102", "192.168.56.103"]

def get_label(dport, proto, src):
    # Ken el source howa el attaquant = attaque
    is_attack = (src == ATTACKER)
    if proto == "ICMP":
        return "normal"
    if not is_attack:
        return "normal"  # trafic eli mch mel attaquant = normal
    if dport == 22:
        return "bruteforce"
    if dport == 21 or dport == 6200:
        return "exploit"
    if dport == 80:
        return "web"
    return "portscan"

print(f"Lecture de {PCAP} ...")
packets = rdpcap(PCAP)
print(f"Total paquets : {len(packets)}")

# Njammaa el paquets 7asb connexion
flows = defaultdict(list)
for pkt in packets:
    if IP in pkt and TCP in pkt:
        key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport, "TCP")
        flows[key].append(pkt)
    elif IP in pkt and ICMP in pkt:
        key = (pkt[IP].src, pkt[IP].dst, 0, "ICMP")
        flows[key].append(pkt)

print(f"Connexions trouvees : {len(flows)}")

rows = []
for key, pkts in flows.items():
    src, dst, dport, proto = key
    label = get_label(dport, proto, src)

    # Feature direction : 1 = men attaquant (داخل l victime), 0 = 5arej
    direction = 1 if src == ATTACKER else 0

    # N9assem l windows
    for i in range(0, len(pkts), WINDOW):
        chunk = pkts[i:i+WINDOW]
        if len(chunk) < 2:
            continue
        nb_packets = len(chunk)
        total_bytes = sum(len(p) for p in chunk)
        times = [float(p.time) for p in chunk]
        duration = max(times) - min(times)
        avg_size = total_bytes / nb_packets

        rows.append({
            "nb_packets": nb_packets,
            "total_bytes": total_bytes,
            "dport": dport,
            "duration": round(duration, 4),
            "avg_size": round(avg_size, 2),
            "direction": direction,
            "label": label
        })

df = pd.DataFrame(rows)
df.to_csv("dataset_v2.csv", index=False)
print(f"\nDataset cree : {len(df)} connexions")
print(df["label"].value_counts())
