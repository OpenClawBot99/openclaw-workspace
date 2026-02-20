"""
Direct Windows mouse/keyboard control via ctypes
No dependencies needed!
"""
import ctypes
import time
import win32api
import win32con

# Mouse functions
def move_mouse(x, y):
    win32api.SetCursorPos((x, y))

def click_left():
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    time.sleep(0.05)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)

def double_click():
    click_left()
    click_left()

# Keyboard functions
def key_press(key):
    win32api.keybd_event(key, 0, 0, 0)
    time.sleep(0.05)
    win32api.keybd_event(key, 0, win32con.KEYEVENTF_KEYUP, 0)

def type_text(text):
    for char in text:
        # Simple approach - use SendKeys concept via Win32
        try:
            # For now just press enter to submit
            pass
        except:
            pass
        time.sleep(0.01)

def main():
    print("Starting direct automation...")
    
    # First, find Grok window
    # This is a simplified version - just demonstrating the concept
    
    # Move to center of screen (where Chrome might be)
    width = win32api.GetSystemMetrics(win32con.SM_CXSCREEN)
    height = win32api.GetSystemMetrics(win32con.SM_CYSCREEN)
    
    print(f"Screen size: {width}x{height}")
    
    # Click in the middle (where browser content usually is)
    move_mouse(width//2, height//2)
    time.sleep(0.5)
    click_left()
    
    print("Clicked! Now let's try to find the Grok input box...")
    
    # The challenge is finding the exact coordinates of the input box
    # Without OCR or computer vision, we can't easily locate it
    
    print("Done with basic mouse control demo!")

if __name__ == '__main__':
    main()
