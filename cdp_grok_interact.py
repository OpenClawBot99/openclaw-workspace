"""
Direct CDP control for Grok - interact and get response
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
    
    # Wait for page load
    time.sleep(8)
    
    # Find input element and type message
    # First, let's get the DOM
    get_dom_msg = json.dumps({
        "id": 3,
        "method": "DOM.getDocument",
        "params": {}
    })
    ws.send(get_dom_msg)
    result = ws.recv()
    print(f"DOM result: {result[:500]}")
    
    # Try to find input box by selector
    query_selector_msg = json.dumps({
        "id": 4,
        "method": "Runtime.evaluate",
        "params": {
            "expression": "document.querySelector('textarea') || document.querySelector('input') || document.querySelector('[contenteditable=\"true\"]')"
        }
    })
    ws.send(query_selector_msg)
    result = ws.recv()
    print(f"Input element: {result[:500]}")
    
    # Type message
    type_msg = json.dumps({
        "id": 5,
        "method": "Runtime.evaluate",
        "params": {
            "expression": """
            const input = document.querySelector('textarea');
            if (input) {
                input.value = '作为黑客，如何快速提升实战技能？请给出具体的学习路径和实战案例';
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.dispatchEvent(new Event('change', { bubbles: true }));
                'success';
            } else {
                'no input found';
            }
            """
        }
    })
    ws.send(type_msg)
    result = ws.recv()
    print(f"Type result: {result}")
    
    # Wait a bit
    time.sleep(2)
    
    # Find and click send button
    click_send_msg = json.dumps({
        "id": 6,
        "method": "Runtime.evaluate",
        "params": {
            "expression": """
            const button = document.querySelector('button[type="submit"]') || 
                          Array.from(document.querySelectorAll('button')).find(b => b.textContent.includes('Send') || b.textContent.includes('发送') || b.querySelector('svg'));
            if (button) {
                button.click();
                'clicked';
            } else {
                'button not found';
            }
            """
        }
    })
    ws.send(click_send_msg)
    result = ws.recv()
    print(f"Click result: {result}")
    
    # Wait for response
    print("Waiting for Grok response...")
    time.sleep(15)
    
    # Take screenshot
    screenshot_msg = json.dumps({
        "id": 7,
        "method": "Page.captureScreenshot",
        "params": {"format": "png"}
    })
    ws.send(screenshot_msg)
    
    result = ws.recv()
    result_data = json.loads(result)
    
    if 'result' in result_data and 'data' in result_data['result']:
        img_data = result_data['result']['data']
        screenshot_path = r'C:\Users\Lenovo\.openclaw\workspace\grok_response.png'
        
        with open(screenshot_path, 'wb') as f:
            f.write(base64.b64decode(img_data))
        
        print(f"Screenshot saved to: {screenshot_path}")
    
    # Try to get response text
    get_response_msg = json.dumps({
        "id": 8,
        "method": "Runtime.evaluate",
        "params": {
            "expression": """
            const messages = document.querySelectorAll('[role="message"], .message, .response');
            if (messages.length > 0) {
                messages[messages.length - 1].innerText;
            } else {
                'no messages found';
            }
            """
        }
    })
    ws.send(get_response_msg)
    result = ws.recv()
    print(f"Response: {result}")
    
    ws.close()
    print("Done!")

if __name__ == '__main__':
    main()
