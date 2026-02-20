# WeChat 文章抓取技能

## 功能
抓取微信文章，支持 JavaScript 渲染内容

## 实现方案

### 方案1: 使用 Selenium
```python
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def fetch_wechat(url):
    options = Options()
    options.add_argument('--headless')
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    return driver.page_source
```

### 方案2: 使用 Playwright
```python
from playwright.sync_api import sync_playwright

def fetch_wechat(url):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url)
        return page.content()
```

### 方案3: 使用 cloudflare Workers (API 方案)
- 绕过 JS 检测的 API 服务

## 需要的依赖
```bash
pip install selenium playwright
playwright install chromium
```

## 状态
⏳ 待开发 - 需要配置浏览器环境
