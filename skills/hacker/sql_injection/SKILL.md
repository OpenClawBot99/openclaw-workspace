# SQL注入Skill

## 简介
SQL注入是一种Web安全漏洞，允许攻击者通过输入恶意SQL语句操纵数据库。

## 漏洞原理

### 1. 原始查询
```sql
SELECT * FROM users WHERE id = '$id'
```

### 2. 恶意输入
```
1' OR '1'='1
```

### 3. 执行结果
```sql
SELECT * FROM users WHERE id = '1' OR '1'='1'
-- 永真条件，返回所有用户
```

## 攻击类型

### 1.  UNION注入
```sql
' UNION SELECT username,password FROM users--
```

### 2. 盲注
- 布尔盲注
- 时间盲注
- 报错盲注

### 3. 堆叠注入
```sql
'; DROP TABLE users;--
```

### 4. 二次注入
- 存储型注入
- 读取时触发

## 检测方法

### 1. 错误信息
- 单引号测试
- 逻辑测试

### 2. 盲注测试
- AND 1=1 / AND 1=2
- SLEEP()测试

## 防御措施

### 1. 参数化查询
```python
# Good
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Bad
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### 2. 输入验证
- 白名单
- 类型检查

### 3. 最小权限
- 数据库账户权限限制

### 4. 错误处理
- 关闭详细错误信息

## 工具

- SQLMap
- Burp Suite
- Havij

---
*目标: 成为世界第一黑客*
*类型: Web安全*
