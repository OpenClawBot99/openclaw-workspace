# 勒索软件(Ransomware)深度分析

## 简介
勒索软件加密受害者文件，要求支付赎金解密。

## 演进历史

### 第一代：加密货币出现前
- 锁定屏幕
- 简单文件加密
- 支付方式：信用卡/银行转账

### 第二代：加密货币时代
- 强加密算法（RSA/AES）
- 匿名支付（比特币）
- Tor通信

### 第三代：RaaS（勒索软件即服务）
- 开发者/运营分离
- 全球化攻击
- 双重勒索

## 技术架构

### 1. 加密模块
```python
# 典型加密流程
class Ransomware:
    def __init__(self):
        # 生成RSA密钥对
        self.private_key = RSA.generate(4096)
        self.public_key = self.private_key.publickey()
        
        # 为每个文件生成AES密钥
        self.file_key = os.urandom(32)  # AES-256
        
    def encrypt_file(self, filepath):
        # 使用AES加密文件内容
        cipher_aes = AES.new(self.file_key, AES.MODE_GCM)
        with open(filepath, 'rb') as f:
            data = f.read()
        ciphertext, tag = cipher_aes.encrypt)
        
        #_and_digest(data 使用RSA加密AES密钥
        encrypted_key = self.public_key.encrypt(
            self.file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
```

### 2. 传播模块
- 漏洞利用（EternalBlue）
- 弱口令（RDP/SSH）
- 钓鱼邮件
- 恶意广告

### 3. 持久化
- 注册表启动项
- 计划任务
- 服务
- WMI事件订阅

### 4. 通信模块
- Tor2Web
- I2P
- 区块链（如Ethereum合约）

## 著名案例

### 1. WannaCry (2017)
- 利用NSA泄露漏洞（永恒之蓝）
- 全球超过23万台电脑感染
- 勒索金额：300-600美元比特币

### 2. NotPetya (2017)
- 伪装成Petya
- 破坏MBR
- 造成全球100亿美元损失

### 3. REvil (2020-2021)
- RaaS模式
- 攻击JBS Foods（肉类加工厂）
- 攻击Kaseya（IT管理软件）

### 4. Conti (2021-2022)
- 双重勒索
- 攻击哥斯达黎加政府
- 逍遥法外（据称）

## 防御策略

### 预防
1. 及时打补丁
2. 强密码策略
3. 多因素认证
4. 邮件过滤
5. 终端防护

### 检测
1. 异常文件访问
2. 加密行为监控
3. 网络流量分析
4. 行为检测

### 响应
1. 隔离感染主机
2. 备份恢复
3. 取证分析
4. 报告执法部门

### 恢复
1. 不支付赎金（鼓励犯罪）
2. 使用解密工具
3. 备份恢复
4. 重建系统

## 检测规则（YARA）
```yaml
rule ransomware {
    meta:
        author = "Security Researcher"
        description = "Ransomware detection"
    strings:
        $a = "WannaCry" nocase
        $b = ".wcry" nocase
        $c = "WANNACRY" nocase
        $d = { 4E 6F 74 50 65 74 79 }  # NotPetya magic
        $e = "encrypted" nocase
        $f = "ransom" nocase
    condition:
        any of them
}
```

## 环境适配

### Windows环境
- 检查杀软状态
- 提权操作
- 域环境利用

### Linux环境
- 检查Samba/NFS
- 加密本地文件
- 容器环境检测

### 网络环境
- 内网：横向传播
- 外网：反弹Shell
- 隔离网络：定时任务

---
*学习时间: 2026-02-21*
*目标: 成为世界第一黑客*
