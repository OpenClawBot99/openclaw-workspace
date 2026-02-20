"""
Complete Grok automation via OS-level mouse/keyboard control
"""
import ctypes
import time
import win32api
import win32con

# Screen dimensions
WIDTH = 2048
HEIGHT = 1152

# Typical Grok input box location (bottom center)
GROK_INPUT_X = WIDTH // 2  
GROK_INPUT_Y = HEIGHT - 150

def move_mouse(x, y):
    win32api.SetCursorPos((x, y))

def click_left():
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    time.sleep(0.1)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)

def double_click():
    click_left()
    click_left()

def type_char(c):
    # Simple typing - maps characters to virtual key codes
    # This is simplified - real implementation would need full keyboard mapping
    vk = ord(c.upper())
    win32api.keybd_event(vk, 0, 0, 0)
    time.sleep(0.05)
    win32api.keybd_event(vk, 0, win32con.KEYEVENTF_KEYUP, 0)

def press_enter():
    win32api.keybd_event(win32con.VK_RETURN, 0, 0, 0)
    time.sleep(0.1)
    win32api.keybd_event(win32con.VK_RETURN, 0, win32con.KEYEVENTF_KEYUP, 0)

def press_tab():
    win32api.keybd_event(win32con.VK_TAB, 0, 0, 0)
    time.sleep(0.1)
    win32api.keybd_event(win32con.VK_TAB, 0, win32con.KEYEVENTF_KEYUP, 0)

def main():
    print("="*50)
    print("Grok Automation via OS-level control")
    print("="*50)
    
    message = "作为黑客，如何快速提升实战技能？请给出具体的学习路径和实战案例"
    
    # Step 1: Move to Grok input area
    print(f"\n1. Moving to input box at ({GROK_INPUT_X}, {GROK_INPUT_Y})...")
    move_mouse(GROK_INPUT_X, GROK_INPUT_Y)
    time.sleep(1)
    
    # Step 2: Click to focus input
    print("2. Clicking on input box...")
    click_left()
    time.sleep(1)
    
    # Step 3: Type message character by character
    print(f"3. Typing message ({len(message)} chars)...")
    for i, char in enumerate(message):
        try:
            # Handle Chinese characters - use clipboard instead
            if ord(char) > 127:
                # Use clipboard for Chinese
                import win32clipboard
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardText(message)
                win32clipboard.CloseClipboard()
                
                # Ctrl+V to paste
                win32api.keybd_event(win32con.VK_CONTROL, 0, 0, 0)
                win32api.keybd_event(ord('V'), 0, 0, 0)
                time.sleep(0.1)
                win32api.keybd_event(ord('V'), 0, win32con.KEYEVENTF_KEYUP, 0)
                win32api.keybd_event(win32con.VK_CONTROL, 0, win32con.KEYEVENTF_KEYUP, 0)
                print("   Pasted Chinese text via clipboard!")
                break
            else:
                type_char(char)
        except Exception as e:
            print(f"   Error typing: {e}")
        if i % 10 == 0:
            print(f"   Progress: {i}/{len(message)}")
        time.sleep(0.05)
    
    time.sleep(1)
    
    # Step 4: Press Enter to send
    print("4. Pressing Enter to send...")
    press_enter()
    
    # Step 5: Wait for response
    print("5. Waiting for Grok response (20 seconds)...")
    time.sleep(20)
    
    print("\n" + "="*50)
    print("Automation complete!")
    print("Check the browser for Grok's response")
    print("="*50)

if __name__ == '__main__':
    main()
