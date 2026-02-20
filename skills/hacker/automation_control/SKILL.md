# 自动化控制Skill - 鼠标键盘模拟

## 简介
模拟鼠标点击、键盘输入等自动化控制技术，是黑客必备的底层技能。

## 核心功能

### 1. 鼠标控制
- 移动鼠标
- 左键点击
- 右键点击
- 双击
- 拖拽
- 滚轮滚动

### 2. 键盘控制
- 键击模拟
- 组合键
- 快捷键
- 文本输入

### 3. 屏幕控制
- 截图
- 坐标获取
- 图像识别
- 区域操作

## Python实现

### 1. pyautogui
```python
import pyautogui

# 鼠标移动
pyautogui.moveTo(x, y, duration=1)

# 点击
pyautogui.click(x, y)
pyautogui.doubleClick(x, y)
pyautogui.rightClick(x, y)

# 键盘输入
pyautogui.typewrite('hello')
pyautogui.press('enter')
pyautogui.hotkey('ctrl', 'c')

# 截图
screenshot = pyautogui.screenshot()
```

### 2. win32api (Windows底层)
```python
import win32api
import win32con

# 鼠标移动
win32api.SetCursorPos((x, y))

# 点击
win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)

# 键盘
win32api.keybd_event(vk_code, 0, 0, 0)
win32api.keybd_event(vk_code, 0, win32con.KEYEVENTF_KEYUP, 0)
```

### 3. 剪贴板(中文输入)
```python
import win32clipboard

# 复制中文到剪贴板
win32clipboard.OpenClipboard()
win32clipboard.EmptyClipboard()
win32clipboard.SetClipboardText('中文内容')
win32clipboard.CloseClipboard()

# Ctrl+V 粘贴
win32api.keybd_event(win32con.VK_CONTROL, 0, 0, 0)
win32api.keybd_event(ord('V'), 0, 0, 0)
win32api.keybd_event(ord('V'), 0, win32con.KEYEVENTF_KEYUP, 0)
win32api.keybd_event(win32con.VK_CONTROL, 0, win32con.KEYEVENTF_KEYUP, 0)
```

### 4. 控制浏览器
```python
# Selenium
from selenium import webdriver
driver = webdriver.Chrome()
driver.get('https://google.com')
driver.find_element_by_name('q').send_keys('test')

# Playwright
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto('https://google.com')
```

## CDP协议 (Chrome DevTools Protocol)

### 1. 启动Chrome with CDP
```bash
chrome.exe --remote-debugging-port=9222 --remote-allow-origins=*
```

### 2. 连接CDP
```python
import urllib.request
import websocket

# 获取endpoint
with urllib.request.urlopen('http://localhost:9222/json') as response:
    data = json.loads(response.read())
    ws_url = data[0]['webSocketDebuggerUrl']

# 连接WebSocket
ws = websocket.create_connection(ws_url)
```

### 3. CDP命令
```python
# 导航
ws.send(json.dumps({
    "id": 1,
    "method": "Page.navigate",
    "params": {"url": "https://example.com"}
}))

# 截图
ws.send(json.dumps({
    "id": 2,
    "method": "Page.captureScreenshot",
    "params": {"format": "png"}
}))

# 执行JS
ws.send(json.dumps({
    "id": 3,
    "method": "Runtime.evaluate",
    "params": {"expression": "document.title"}
}))
```

## 实际应用

### 1. 浏览器自动化
- 自动填表
- 批量操作
- 定时任务

### 2. UI测试
- 自动化测试
- 回归测试

### 3. 截图识别
- OCR自动化
- 图像对比

### 4. 游戏辅助
- 自动操作
- 脚本录制

## 安全与检测

### 1. 反检测
- 随机延迟
- 模拟人类
- 轨迹变化

### 2. 检测工具
- 鼠标轨迹分析
- 键盘时序分析

## 注意事项

### 1. 安全
- 避免滥用
- 隐私保护
- 权限合规

### 2. 稳定性
- 添加延迟
- 错误处理
- 坐标校验

---
*目标: 成为世界第一黑客*
*类型: 自动化控制*
