"""
CDP Grok - connect via existing OpenClaw browser WebSocket
"""
import json
import websocket
import base64
import time

def main():
    # Use the WebSocket from OpenClaw's tab
    ws_url = "ws://127.0.0.1:18800/devtools/page/01DE18E9A4C15A55DCCF6CC12668B8C0"
    
    print(f"Connecting to: {ws_url}")
    
    try:
        ws = websocket.create_connection(ws_url, timeout=10)
        print("Connected!")
    except Exception as e:
        print(f"Connection error: {e}")
        return
    
    # Fill input
    ws.send(json.dumps({
        "id": 1, 
        "method": "Runtime.evaluate", 
        "params": {"expression": """
            const textarea = document.querySelector('textarea');
            if(textarea) {
                textarea.value = '作为黑客，如何快速提升实战技能？请给出具体的学习路径和实战案例';
                textarea.dispatchEvent(new Event('input', {bubbles: true}));
                'filled';
            } else {
                'not found: ' + document.querySelectorAll('*').length;
            }
        """}
    }))
    result = ws.recv()
    print(f"Fill result: {result[:200]}")
    time.sleep(2)
    
    # Click send button
    ws.send(json.dumps({
        "id": 2, 
        "method": "Runtime.evaluate", 
        "params": {"expression": """
            const buttons = document.querySelectorAll('button');
            for(const btn of buttons) {
                if(btn.textContent.includes('Send') || btn.querySelector('svg')) {
                    btn.click();
                    'clicked';
                    break;
                }
            }
        """}
    }))
    result = ws.recv()
    print(f"Click result: {result[:200]}")
    
    # Wait for response
    print("Waiting 15s for response...")
    time.sleep(15)
    
    # Screenshot
    ws.send(json.dumps({"id": 3, "method": "Page.captureScreenshot", "params": {"format": "png"}}))
    result = ws.recv()
    try:
        result_data = json.loads(result)
        if 'result' in result_data and 'data' in result_data['result']:
            with open(r'C:\Users\Lenovo\.openclaw\workspace\grok_result.png', 'wb') as f:
                f.write(base64.b64decode(result_data['result']['data']))
            print("Screenshot saved to grok_result.png!")
    except Exception as e:
        print(f"Screenshot error: {e}")
    
    # Get response text
    ws.send(json.dumps({
        "id": 4, 
        "method": "Runtime.evaluate", 
        "params": {"expression": "document.body.innerText.substring(0, 3000)"}
    }))
    result = ws.recv()
    print(f"Page text: {result[:1000]}")
    
    ws.close()
    print("Done!")

if __name__ == '__main__':
    main()
