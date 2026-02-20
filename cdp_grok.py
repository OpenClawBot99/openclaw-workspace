"""
Direct CDP control for Grok - with screenshot saving
"""
import json
import urllib.request
import websocket
import base64
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
    import time
    time.sleep(10)
    
    # Take screenshot
    screenshot_msg = json.dumps({
        "id": 2,
        "method": "Page.captureScreenshot",
        "params": {"format": "png"}
    })
    ws.send(screenshot_msg)
    
    result = ws.recv()
    result_data = json.loads(result)
    
    if 'result' in result_data and 'data' in result_data['result']:
        # Save screenshot
        img_data = result_data['result']['data']
        screenshot_path = r'C:\Users\Lenovo\.openclaw\workspace\grok_screenshot.png'
        
        with open(screenshot_path, 'wb') as f:
            f.write(base64.b64decode(img_data))
        
        print(f"Screenshot saved to: {screenshot_path}")
    else:
        print(f"Error: {result}")
    
    ws.close()
    print("Done!")

if __name__ == '__main__':
    main()
