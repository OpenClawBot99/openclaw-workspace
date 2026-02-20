#!/usr/bin/env python3
"""
Wireshark PCAP分析脚本
功能: 提取HTTP请求、图片、敏感信息
"""

import sys
import os
from pathlib import Path


def check_dependencies():
    """检查依赖"""
    try:
        import scapy
        print("[*] scapy 已安装")
        return True
    except ImportError:
        print("[!] 请安装 scapy: pip install scapy")
        return False


def extract_http_images(pcap_file, output_dir):
    """从PCAP中提取HTTP图片"""
    try:
        from scapy.all import rdpcap, TCP, Raw
    except:
        print("[!] 需要安装 scapy")
        return
    
    print(f"[*] 读取: {pcap_file}")
    packets = rdpcap(pcap_file)
    
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    
    image_count = 0
    
    for pkt in packets:
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            
            # JPEG
            if data.startswith(b'\xff\xd8\xff'):
                ext = 'jpg'
            # PNG
            elif data.startswith(b'\x89PNG'):
                ext = 'png'
            # GIF
            elif data.startswith(b'GIF89a') or data.startswith(b'GIF87a'):
                ext = 'gif'
            else:
                continue
            
            filename = f"image_{image_count}.{ext}"
            filepath = output / filename
            
            with open(filepath, 'wb') as f:
                f.write(data[:100000])  # 限制大小
            
            print(f"[+] 提取: {filename}")
            image_count += 1
    
    print(f"\n[+] 总共提取 {image_count} 张图片")


def extract_http_requests(pcap_file, output_file):
    """提取所有HTTP请求"""
    try:
        from scapy.all import rdpcap, TCP, Raw
    except:
        print("[!] 需要安装 scapy")
        return
    
    print(f"[*] 读取: {pcap_file}")
    packets = rdpcap(pcap_file)
    
    http_requests = []
    
    for pkt in packets:
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            
            # 检查HTTP请求
            if b'GET ' in data or b'POST ' in data:
                try:
                    text = data.decode('utf-8', errors='ignore')
                    if 'HTTP/' in text:
                        # 提取请求行
                        lines = text.split('\r\n')
                        if lines:
                            http_requests.append(lines[0])
                except:
                    pass
    
    # 保存结果
    with open(output_file, 'w', encoding='utf-8') as f:
        for req in http_requests:
            f.write(req + '\n')
    
    print(f"[+] 保存 {len(http_requests)} 个HTTP请求到: {output_file}")


def extract_credentials(pcap_file):
    """提取可能包含的凭证"""
    try:
        from scapy.all import rdpcap, TCP, Raw
    except:
        print("[!] 需要安装 scapy")
        return
    
    print(f"[*] 读取: {pcap_file}")
    packets = rdpcap(pcap_file)
    
    # 凭证关键词
    keywords = [
        b'Authorization:',
        b'Basic ',
        b'username=',
        b'password=',
        b'login=',
        b'token=',
        b'session',
    ]
    
    credentials = []
    
    for pkt in packets:
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            
            for kw in keywords:
                if kw.lower() in data.lower():
                    try:
                        text = data.decode('utf-8', errors='ignore')
                        # 提取包含关键词的行
                        for line in text.split('\r\n'):
                            if any(k.decode() in line.lower() for k in keywords):
                                credentials.append(line.strip())
                    except:
                        pass
    
    # 去重
    credentials = list(set(credentials))
    
    print(f"\n[*] 发现 {len(credentials)} 个可能包含凭证的行:")
    for cred in credentials[:20]:  # 限制显示
        print(f"  - {cred[:80]}...")
    
    if len(credentials) > 20:
        print(f"  ... 还有 {len(credentials) - 20} 个")


def analyze_dns(pcap_file):
    """分析DNS查询"""
    try:
        from scapy.all import rdpcap, DNS, DNSQR
    except:
        print("[!] 需要安装 scapy")
        return
    
    print(f"[*] 读取: {pcap_file}")
    packets = rdpcap(pcap_file)
    
    dns_queries = set()
    
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS查询
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            dns_queries.add(query)
    
    print(f"\n[*] DNS查询 ({len(dns_queries)} 个):")
    for query in sorted(dns_queries):
        print(f"  - {query}")


def pcap_to_json(pcap_file, output_file):
    """导出PCAP为JSON格式"""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except:
        print("[!] 需要安装 scapy")
        return
    
    import json
    
    print(f"[*] 读取: {pcap_file}")
    packets = rdpcap(pcap_file)
    
    results = []
    
    for i, pkt in enumerate(packets):
        packet_info = {
            "frame": i + 1,
        }
        
        if pkt.haslayer(IP):
            packet_info["src_ip"] = pkt[IP].src
            packet_info["dst_ip"] = pkt[IP].dst
            packet_info["protocol"] = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "IP"
            packet_info["length"] = len(pkt)
        
        results.append(packet_info)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] 导出 {len(results)} 个数据包到: {output_file}")


def main():
    print("="*60)
    print("Wireshark PCAP 分析工具")
    print("="*60)
    
    if not check_dependencies():
        return
    
    print("\n功能:")
    print("[1] 提取HTTP图片")
    print("[2] 提取HTTP请求")
    print("[3] 提取凭证")
    print("[4] 分析DNS查询")
    print("[5] 导出JSON")
    
    choice = input("\n选择: ").strip()
    pcap_file = input("PCAP文件: ").strip()
    
    if not os.path.exists(pcap_file):
        print(f"[x] 文件不存在: {pcap_file}")
        return
    
    if choice == '1':
        output_dir = input("输出目录 [images]: ").strip() or "images"
        extract_http_images(pcap_file, output_dir)
    elif choice == '2':
        output_file = input("输出文件 [http_requests.txt]: ").strip() or "http_requests.txt"
        extract_http_requests(pcap_file, output_file)
    elif choice == '3':
        extract_credentials(pcap_file)
    elif choice == '4':
        analyze_dns(pcap_file)
    elif choice == '5':
        output_file = input("输出文件 [packets.json]: ").strip() or "packets.json"
        pcap_to_json(pcap_file, output_file)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # 命令行模式
        pcap_file = sys.argv[1]
        mode = sys.argv[2] if len(sys.argv) > 2 else "requests"
        
        if mode == "images":
            extract_http_images(pcap_file, "images")
        elif mode == "credentials":
            extract_credentials(pcap_file)
        elif mode == "dns":
            analyze_dns(pcap_file)
        else:
            extract_http_requests(pcap_file, "http_requests.txt")
    else:
        main()
