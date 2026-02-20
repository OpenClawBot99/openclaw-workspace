"""
Direct CDP control for Grok - simplified interaction
"""
import json
import urllib.request
import websocket
import base64
import time
import os

def main():
    # Get CDP endpoints
    with urllib.request.urlopen('http://localhost:9222/json') as response:
        data = json.loads(response.read())
        ws_url = data[0]['webSocketDebuggerUrl']
    
    print(f"Connecting to: {ws_url}")
    
    ws = websocket.create_connection(ws_url)
    
    # Navigate to Grok
    msg = json.dumps({
        "id": 1,
        "method": "Page.navigate",
        "params": {"url": "https://grok.com"}
    })
    ws.send(msg)
    print("Navigating to Grok...")
    
    # Wait for page load - longer wait
    time.sleep(12)
    
    # Take initial screenshot
    screenshot_msg = json.dumps({
        "id": 2,
        "method": "Page.captureScreenshot",
        "params": {"format": "png"}
    })
    ws.send(screenshot_msg)
    result = ws.recv()
    result_data = json.loads(result)
    
    if 'result' in result_data and 'data' in result_data['result']:
        img_data = result_data['result']['data']
        screenshot_path = r'C:\Users\Lenovo\.openclaw\workspace\grok_step1.png'
        
        with open(screenshot_path, 'wb') as f:
            f.write(base64.b64decode(img_data))
        
        print(f"Screenshot 1 saved to: {screenshot_path}")
    
    # Get page HTML to find input
    html_msg = json.dumps({
        "id": 3,
        "method": "Runtime.evaluate",
        "params": {
            "expression": "document.body.innerHTML.substring(0, 2000)"
        }
    })
    ws.send(html_msg)
    result = ws.recv()
    print(f"Page HTML: {result[:1000]}")
    
    # Try to find and fill input
    fill_msg = json.dumps({
        "id": 4,
        "method": "Runtime.evaluate",
        "params": {
            "expression": """
            // Try different selectors
            const selectors = ['textarea[placeholder*="Message"]', 'textarea', 'input[type="text"]', '[contenteditable="true"]'];
            for (const sel of selectors) {
                const el = document.querySelector(sel);
                if (el) {
                    el.focus();
                    el.value = '作为黑客，如何快速提升实战技能？请给出具体的学习路径和实战案例';
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    console.log('Filled element:', sel);
                    break;
                }
            }
            'done'
            """
        }
    })
    ws.send(fill_msg)
    result = ws.recv()
    print(f"Fill result: {result}")
    
    time.sleep(2)
    
    # Click send button
    click_msg = json.dumps({
        "id": 5,
        "method": "Runtime.evaluate",
        "params": {
            "expression": """
            // Find send button
            const buttons = document.querySelectorAll('button');
            for (const btn of buttons) {
                if (btn.textContent.includes('Send') || btn.querySelector('svg')) {
                    btn.click();
                    console.log('Clicked button');
                    break;
                }
            }
            'clicked'
            """
        }
    })
    ws.send(click_msg)
    result = ws.recv()
    print(f"Click result: {result}")
    
    # Wait for response
    print("Waiting for Grok response (15s)...")
    time.sleep(15)
    
    # Take screenshot after response
    screenshot_msg2 = json.dumps({
        "id": 6,
        "method": "Page.captureScreenshot",
        "params": {"format": "png"}
    })
    ws.send(screenshot_msg2)
    result = ws.recv()
    result_data = json.loads(result)
    
    if 'result' in result_data and 'data' in result_data['result']:
        img_data = result_data['result']['data']
        screenshot_path = r'C:\Users\Lenovo\.openclaw\workspace\grok_response.png'
        
        with open(screenshot_path, 'wb') as f:
            f.write(base64.b64decode(img_data))
        
        print(f"Response screenshot saved to: {screenshot_path}")
    
    # Try to extract response text
    extract_msg = json.dumps({
        "id": 7,
        "method": "Runtime.evaluate",
        "params": {
            "expression": """
            // Try to find response text
            const divs = document.querySelectorAll('div');
            let responseText = '';
            for (const d of divs) {
                if (d.textContent.length > 100 && d.textContent.includes('黑客')) {
                    responseText = d.textContent.substring(0, 500);
                    break;
                }
            }
            responseText || 'response not found'
            """
        }
    })
    ws.send(extract_msg)
    result = ws.recv()
    print(f"Extracted response: {result}")
    
    ws.close()
    print("Done!")

if __name__ == '__main__':
    main()
