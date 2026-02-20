"""
CDP连接修复工具
尝试使用Python直接连接CDP
"""
import asyncio
from pyppeteer import launch

async def main():
    browser = await launch(
        headless=False,
        args=['--no-sandbox', '--disable-setuid-sandbox']
    )
    page = await browser.newPage()
    await page.goto('https://grok.com')
    await asyncio.sleep(5)
    await browser.close()

if __name__ == '__main__':
    asyncio.run(main())
