"""
Grok automation - OS level control
"""
import win32api, win32con, win32clipboard
import time
import os

WIDTH = 2048
HEIGHT = 1152

def move_click(x, y):
    win32api.SetCursorPos((x, y))
    time.sleep(0.3)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    time.sleep(0.1)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)

def paste_text(text):
    win32clipboard.OpenClipboard()
    win32clipboard.EmptyClipboard()
    win32clipboard.SetClipboardText(text)
    win32clipboard.CloseClipboard()
    time.sleep(0.2)
    # Ctrl+V
    win32api.keybd_event(win32con.VK_CONTROL, 0, 0, 0)
    win32api.keybd_event(ord('V'), 0, 0, 0)
    time.sleep(0.1)
    win32api.keybd_event(ord('V'), 0, win32con.KEYEVENTF_KEYUP, 0)
    win32api.keybd_event(win32con.VK_CONTROL, 0, win32con.KEYEVENTF_KEYUP, 0)

def press_enter():
    win32api.keybd_event(win32con.VK_RETURN, 0, 0, 0)
    time.sleep(0.1)
    win32api.keybd_event(win32con.VK_RETURN, 0, win32con.KEYEVENTF_KEYUP, 0)

def main():
    print("=== Grok Automation ===")
    
    # Step 1: Click on input area
    print("1. Clicking input box...")
    move_click(WIDTH//2, HEIGHT-200)
    time.sleep(2)
    
    # Step 2: Paste question
    print("2. Pasting question...")
    question = "作为黑客，如何快速提升实战技能？请给出具体的学习路径和实战案例"
    paste_text(question)
    time.sleep(1)
    
    # Step 3: Send
    print("3. Pressing Enter...")
    press_enter()
    
    # Step 4: Wait
    print("4. Waiting for response (25s)...")
    time.sleep(25)
    
    print("=== Done! Check browser for response ===")

if __name__ == '__main__':
    main()
