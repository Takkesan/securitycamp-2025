from scapy.all import *
import time

def get_gateway_mac(gw_ip, iface):
    ans, _ = arping(gw_ip, iface=iface, verbose=0)
    for snd, rcv in ans:
        return rcv[Ether].src
    raise Exception("ゲートウェイのMACアドレスが取得できませんでした")

def send_spoofed_txt_query(src_ip, target_ip, qname, iface, gw_ip):
    print(f"\n[+] Spoofed TXT query from {src_ip} to {target_ip} for domain {qname}")

    mac = get_gateway_mac(gw_ip, iface)
    print(f"[+] Gateway MAC: {mac}")

    ether = Ether(dst=mac)
    ip = IP(src=src_ip, dst=target_ip)
    udp = UDP(sport=RandShort(), dport=53)
    dns = DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))  # ← TXT のみ
    pkt = ether / ip / udp / dns

    sendp(pkt, iface=iface, verbose=1)

# --- 設定セクション ---
iface = "enp1s0"                 # ゲストOSのNIC名
src_ip = "192.168.11.25"         # ホストOSのIP（偽装送信元）
dns_target_ip = "1.1.1.1"        # Cloudflare DNS
gw_ip = "192.168.11.1"           # ゲートウェイのIP
domain = "takkesan.com"          # テスト用ドメイン

# --- 実行 ---
send_spoofed_txt_query(src_ip, dns_target_ip, domain, iface, gw_ip)

