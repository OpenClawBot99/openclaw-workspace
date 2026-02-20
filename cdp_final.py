"""
CDP Grok automation - complete workflow
"""
import json
import urllib.request
import websocket
import base64
import time

def main():
    # Get CDP endpoint
    try:
        with urllib.request.urlopen('http://localhost:9223/json', timeout=5) as response:
            data = json.loads(response.read())
            ws_url = data[0]['webSocketDebuggerUrl']
            print(f"Connected to: {data[0]['title']}")
    except Exception as e:
        print(f"Error connecting: {e}")
        return
    
    ws = websocket.create_connection(ws_url)
    
    # Navigate to Grok
    ws.send(json.dumps({
        "id": 1, 
        "method": "Page.navigate", 
        "params": {"url": "https://grok.com"}
    }))
    print("Navigating to Grok...")
    time.sleep(10)
    
    # Get page info
    ws.send(json.dumps({"id": 2, "method": "Runtime.evaluate", "params": {"expression": "document.title"}}))
    result = ws.recv()
    print(f"Page title: {result}")
    
    # Fill input
    ws.send(json.dumps({
        "id": 3, 
        "method": "Runtime.evaluate", 
        "params": {"expression": """
            const textarea = document.querySelector('textarea');
            if(textarea) {
                textarea.value = '作为黑客，如何快速提升实战技能？请给出具体的学习路径和实战案例';
                textarea.dispatchEvent(new Event('input', {bubbles: true}));
                'filled';
            } else {
                'not found'
            }
        """}
    }))
    result = ws.recv()
    print(f"Fill result: {result}")
    time.sleep(2)
    
    # Click send
    ws.send(json.dumps({
        "id": 4, 
        "method": "Runtime.evaluate", 
        "params": {"expression": """
            const btn = document.querySelector('button') || document.querySelector('[role="button"]');
            if(btn) { btn.click(); 'clicked'; } else { 'not found'; }
        """}
    }))
    result = ws.recv()
    print(f"Click result: {result}")
    
    # Wait for response
    print("Waiting for response...")
    time.sleep(20)
    
    # Screenshot
    ws.send(json.dumps({"id": 5, "method": "Page.captureScreenshot", "params": {"format": "png"}}))
    result = ws.recv()
    result_data = json.loads(result)
    
    if 'result' in result_data and 'data' in result_data['result']:
        with open(r'C:\Users\Lenovo\.openclaw\workspace\grok_result.png', 'wb') as f:
            f.write(base64.b64decode(result_data['result']['data']))
        print("Screenshot saved!")
    
    # Get response text
    ws.send(json.dumps({
        "id": 6, 
        "method": "Runtime.evaluate", 
        "params": {"expression": "document.body.innerText.substring(0, 2000)"}
    }))
    result = ws.recv()
    print(f"Response: {result[:500]}...")
    
    ws.close()
    print("Done!")

if __name__ == '__main__':
    main()
