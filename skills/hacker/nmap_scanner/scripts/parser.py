#!/usr/bin/env python3
"""
Nmap扫描结果分析脚本
用法: python nmap_parser.py scan.xml
"""

import xml.etree.ElementTree as ET
import sys
import json


def parse_nmap_xml(xml_file):
    """解析Nmap XML输出"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"[x] 解析XML失败: {e}")
        return
    
    results = {
        "hosts": [],
        "stats": {}
    }
    
    # 获取扫描信息
    runinfo = root.find('runstats')
    if runinfo is not None:
        finished = runinfo.find('finished')
        if finished is not None:
            results["stats"]["finish_time"] = finished.get('timestr')
            results["stats"]["elapsed"] = finished.get('elapsed')
    
    # 解析主机
    for host in root.findall('host'):
        host_info = {
            "ip": "",
            "status": "",
            "ports": [],
            "os": [],
            "services": []
        }
        
        # IP地址
        address = host.find('address')
        if address is not None:
            host_info["ip"] = address.get('addr')
        
        # 状态
        status = host.find('status')
        if status is not None:
            host_info["status"] = status.get('state')
        
        # 端口
        for port in host.findall('ports/port'):
            port_info = {
                "portid": port.get('portid'),
                "protocol": port.get('protocol'),
                "state": port.get('state'),
                "service": "",
                "version": ""
            }
            
            # 服务信息
            service = port.find('service')
            if service is not None:
                port_info["service"] = service.get('name')
                port_info["version"] = service.get('version', '')
                port_info["product"] = service.get('product', '')
            
            host_info["ports"].append(port_info)
        
        # 操作系统
        os = host.find('os')
        if os is not None:
            for osmatch in os.findall('osmatch'):
                host_info["os"].append({
                    "name": osmatch.get('name'),
                    "accuracy": osmatch.get('accuracy')
                })
        
        results["hosts"].append(host_info)
    
    return results


def print_results(results):
    """打印结果"""
    print("\n" + "="*60)
    print("Nmap 扫描结果分析")
    print("="*60)
    
    # 统计信息
    if results["stats"]:
        print(f"\n[*] 扫描耗时: {results['stats'].get('elapsed', 'N/A')} 秒")
        print(f"[*] 完成时间: {results['stats'].get('finish_time', 'N/A')}")
    
    # 主机信息
    for host in results["hosts"]:
        print(f"\n[+] 主机: {host['ip']} ({host['status']})")
        
        # 操作系统
        if host["os"]:
            print(f"    操作系统: {host['os'][0]['name']} (准确度: {host['os'][0]['accuracy']}%)")
        
        # 开放端口
        open_ports = [p for p in host["ports"] if p["state"] == "open"]
        if open_ports:
            print(f"    开放端口 ({len(open_ports)}):")
            for port in open_ports:
                service = port["service"] or "unknown"
                version = f" {port['version']}" if port["version"] else ""
                print(f"      - {port['portid']}/{port['protocol']}: {service}{version}")


def export_json(results, output_file):
    """导出JSON"""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[+] 结果已导出到: {output_file}")


def export_txt(results, output_file):
    """导出文本报告"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("Nmap 扫描结果\n")
        f.write("="*60 + "\n\n")
        
        for host in results["hosts"]:
            f.write(f"主机: {host['ip']}\n")
            f.write(f"状态: {host['status']}\n")
            
            if host["os"]:
                f.write(f"操作系统: {host['os'][0]['name']}\n")
            
            open_ports = [p for p in host["ports"] if p["state"] == "open"]
            if open_ports:
                f.write("开放端口:\n")
                for port in open_ports:
                    f.write(f"  - {port['portid']}/{port['protocol']}: {port['service']}\n")
            
            f.write("\n")
    
    print(f"[+] 报告已导出到: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python nmap_parser.py <nmap.xml> [输出文件]")
        print("示例: python nmap_parser.py scan.xml report.json")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"[*] 解析文件: {xml_file}")
    results = parse_nmap_xml(xml_file)
    
    if results:
        print_results(results)
        
        if output_file:
            if output_file.endswith('.json'):
                export_json(results, output_file)
            else:
                export_txt(results, output_file)
