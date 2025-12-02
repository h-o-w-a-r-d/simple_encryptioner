# -*- coding: utf-8 -*-
# 檔案名稱: secure_packer.py
# 功能: 一個支援 GUI 和 CLI 的檔案打包、壓縮與加密工具。
#      - 支援拖曳檔案到 GUI 視窗或 .exe 執行檔。
#      - CLI 模式下能自動判斷環境，使用終端機密碼輸入或彈出式視窗。

import tkinter as tk
from tkinter import filedialog, messagebox
import gzip
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
from tkinterdnd2 import DND_FILES, TkinterDnD
import tkinter.font as tkFont
import tarfile
import io
import sys
import getpass # 用於真實的終端機環境

# --- 加密核心函式 ---

def generate_salt():
    """生成一個隨機的鹽。"""
    return os.urandom(16)

def derive_key(password, salt):
    """從密碼和鹽派生金鑰。"""
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def encrypt_data(data, password):
    """使用密碼加密資料。"""
    salt = generate_salt()
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    return salt + encrypted_data

def decrypt_data(encrypted_data_with_salt, password):
    """使用密碼解密資料。"""
    try:
        salt = encrypted_data_with_salt[:16]
        encrypted_data = encrypted_data_with_salt[16:]
        key = derive_key(password, salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data
    except Exception as e:
        # 統一將錯誤訊息導向 print，GUI 模式下再用 messagebox 顯示
        print(f"錯誤：解密失敗：{e}\n密碼或檔案可能不正確。")
        return None

# --- 壓縮/打包函式 ---

def compress_data(data):
    """使用 gzip 壓縮資料。"""
    return gzip.compress(data, compresslevel=1)

def decompress_data(compressed_data):
    """解壓縮 gzip 資料。"""
    try:
        return gzip.decompress(compressed_data)
    except gzip.BadGzipFile:
        print("錯誤：提供的資料不是有效的 gzip 格式，或已損壞。")
        return None

def find_common_path(paths):
    """找到路徑列表的共同根目錄。"""
    if not paths:
        return ""
    if len(paths) == 1:
        return os.path.dirname(paths[0])
    dir_paths = [os.path.dirname(p) for p in paths]
    return os.path.commonpath(dir_paths)

def create_tar_bundle(file_paths):
    """
    將多個檔案安全地打包成 tar 格式的 in-memory 物件。
    使用 arcname 參數儲存相對路徑，不使用 os.chdir()。
    """
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
        common_root = find_common_path(file_paths)
        for file_path in file_paths:
            if common_root and file_path.startswith(os.path.abspath(common_root)):
                arcname = os.path.relpath(file_path, common_root)
            else:
                arcname = os.path.basename(file_path)
            tar.add(file_path, arcname=arcname)
    tar_buffer.seek(0)
    return tar_buffer.getvalue()

def extract_tar_bundle(tar_data, output_dir):
    """從 tar 資料中安全地提取檔案。"""
    tar_buffer = io.BytesIO(tar_data)
    try:
        with tarfile.open(fileobj=tar_buffer, mode='r') as tar:
            # 使用 Python 3.12+ 的 data filter 來增強安全性
            if sys.version_info >= (3, 12):
                tar.extractall(path=output_dir, filter='data')
            else:
                # 對於舊版 Python，手動進行安全檢查
                members_to_extract = []
                output_path_abs = os.path.abspath(output_dir)
                for member in tar.getmembers():
                    dest_path_abs = os.path.abspath(os.path.join(output_dir, member.name))
                    if not dest_path_abs.startswith(output_path_abs):
                        print(f"安全性警告：檔案 '{member.name}' 包含可疑路徑，跳過提取。")
                        continue
                    members_to_extract.append(member)
                tar.extractall(path=output_dir, members=members_to_extract)
        return True
    except Exception as e:
        print(f"錯誤：解包或提取檔案時發生錯誤：{e}")
        return False

# --- 主要處理流程 ---

def compress_encrypt_process(file_paths, password, is_tty=False):
    """
    加密流程的主函式。
    is_tty 用於區分真終端機(print)和拖曳模式(messagebox)。
    """
    try:
        if is_tty: print("步驟 1/3：正在打包檔案...")
        tar_data = create_tar_bundle(file_paths)

        if is_tty: print("步驟 2/3：正在壓縮資料...")
        compressed_tar_data = compress_data(tar_data)

        if is_tty: print("步驟 3/3：正在加密資料...")
        encrypted_with_salt = encrypt_data(compressed_tar_data, password)

        output_dir = os.path.dirname(file_paths[0]) if file_paths else "."
        # 產生一個較為合理的預設檔名
        base_name = os.path.basename(os.path.splitext(file_paths[0])[0])
        output_file = os.path.join(output_dir, f"{base_name}_bundle.encrypt")

        if os.path.exists(output_file):
            if is_tty:
                response = input(f"輸出檔案 '{output_file}' 已存在，是否要覆蓋？(y/n): ").lower()
                if response != 'y':
                    print("操作已取消。")
                    return
            else: # 拖曳模式或 GUI 模式用 messagebox
                if not messagebox.askyesno("確認", f"輸出檔案 '{output_file}' 已存在，是否要覆蓋？"):
                    messagebox.showinfo("取消", "操作已取消。")
                    return

        with open(output_file, 'wb') as f_out:
            f_out.write(encrypted_with_salt)

        success_message = f"成功：{len(file_paths)} 個檔案已打包、壓縮並加密為 '{output_file}'。"
        if is_tty: print(success_message)
        else: messagebox.showinfo("成功", success_message)
    except Exception as e:
        error_message = f"錯誤：處理過程中發生錯誤：{e}"
        if is_tty: print(error_message)
        else: messagebox.showerror("錯誤", error_message)

def decrypt_decompress_process(input_file, password, is_tty=False):
    """解密流程的主函式。"""
    try:
        if is_tty: print("步驟 1/3：正在解密資料...")
        with open(input_file, 'rb') as f_in:
            encrypted_with_salt = f_in.read()
        decrypted_data = decrypt_data(encrypted_with_salt, password)
        if decrypted_data is None:
            if not is_tty: messagebox.showerror("解密失敗", "密碼或檔案不正確。")
            return

        if is_tty: print("步驟 2/3：正在解壓縮資料...")
        tar_data = decompress_data(decrypted_data)
        if tar_data is None:
            if not is_tty: messagebox.showerror("錯誤", "解壓縮失敗，檔案可能已損壞。")
            return

        if is_tty: print("步驟 3/3：正在解包檔案...")
        output_dir = os.path.dirname(input_file) or "."
        if not extract_tar_bundle(tar_data, output_dir):
            if not is_tty: messagebox.showerror("錯誤", "提取檔案失敗，檔案可能已損壞。")
            return

        success_message = f"成功：檔案 '{input_file}' 已解密並解壓縮至 '{output_dir}'。"
        if is_tty: print(success_message)
        else: messagebox.showinfo("成功", success_message)
    except Exception as e:
        error_message = f"錯誤：處理過程中發生錯誤：{e}"
        if is_tty: print(error_message)
        else: messagebox.showerror("錯誤", error_message)

# --- 非互動式 CLI 模式的密碼輸入視窗 ---

def cli_password_dialog():
    """
    用於「拖曳到執行檔」情境下的密碼輸入 GUI 視窗。
    """
    password_var = tk.StringVar()
    root = tk.Tk()
    root.withdraw()

    dialog = tk.Toplevel(root)
    dialog.title("輸入密碼")
    dialog.resizable(False, False)
    
    def on_ok(event=None):
        password_var.set(entry.get())
        dialog.destroy()

    def on_cancel(event=None):
        password_var.set("")
        dialog.destroy()

    tk.Label(dialog, text="請輸入密碼:", font=("Arial", 10)).pack(padx=20, pady=10)
    entry = tk.Entry(dialog, show="*", width=35, font=("Arial", 10))
    entry.pack(padx=20, pady=5)
    entry.focus_set()

    btn_frame = tk.Frame(dialog)
    btn_frame.pack(padx=20, pady=10)
    tk.Button(btn_frame, text="確定", command=on_ok, default="active", width=8).pack(side="left", padx=5)
    tk.Button(btn_frame, text="取消", command=on_cancel, width=8).pack(side="right", padx=5)

    dialog.bind("<Return>", on_ok)
    dialog.bind("<Escape>", on_cancel)
    dialog.protocol("WM_DELETE_WINDOW", on_cancel)

    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
    y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
    dialog.geometry(f"+{x}+{y}")
    
    root.wait_window(dialog)
    root.destroy()
    
    return password_var.get()

# --- GUI 相關函式與主介面 ---

input_files_list = []
def browse_input_files():
    """開啟對話方塊讓使用者選擇檔案。"""
    filenames = filedialog.askopenfilenames()
    if filenames:
        global input_files_list
        input_files_list = list(filenames)
        update_drop_area_text()

def drop_handler(event):
    """處理拖曳到視窗的檔案。"""
    paths_str = event.data.strip()
    if paths_str.startswith('{') and paths_str.endswith('}'):
        file_paths = [p.strip() for p in paths_str[1:-1].split('} {')]
    else:
        file_paths = paths_str.split('\n')
    global input_files_list
    input_files_list = [os.path.normpath(path) for path in file_paths if path]
    update_drop_area_text()

def update_drop_area_text():
    """更新拖放區域的提示文字。"""
    if not input_files_list:
        drop_area_var.set("拖曳檔案至此或點擊瀏覽")
        drop_area.config(fg="#555555")
    elif len(input_files_list) == 1:
        drop_area_var.set(input_files_list[0])
        drop_area.config(fg="black")
    else:
        drop_area_var.set(f"{len(input_files_list)} 個檔案已選取")
        drop_area.config(fg="black")

def process_button_click():
    """處理按鈕點擊事件。"""
    password = password_entry.get()
    if not input_files_list or not password:
        messagebox.showerror("錯誤", "請選擇檔案並輸入密碼。")
        return

    process_button.config(text="處理中...", state="disabled")
    window.update_idletasks()
    
    try:
        is_decrypt = len(input_files_list) == 1 and input_files_list[0].lower().endswith(".encrypt")
        if is_decrypt:
            decrypt_decompress_process(input_files_list[0], password, is_tty=False)
        else:
            compress_encrypt_process(input_files_list, password, is_tty=False)
    finally:
        global input_files_list
        input_files_list = []
        update_drop_area_text()
        password_entry.delete(0, tk.END)
        process_button.config(text="處理 (壓縮/加密 或 解密/解壓縮)", state="normal")

# --- 主程式進入點 ---

if __name__ == "__main__":
    # 模式 1: 命令列模式 (有參數)
    if len(sys.argv) > 1:
        cli_file_paths = sys.argv[1:]
        
        # 判斷是哪種 CLI 模式
        is_interactive_tty = sys.stdin.isatty()
        password = ""

        if is_interactive_tty:
            # 真實終端機，使用 getpass
            print("在互動式終端機模式下執行...")
            try:
                password = getpass.getpass("請輸入密碼: ")
            except (KeyboardInterrupt, EOFError):
                print("\n操作已由使用者中斷。")
                sys.exit(1)
        else:
            # 拖曳到執行檔，彈出 GUI
            password = cli_password_dialog()

        if not password:
            if is_interactive_tty:
                print("未輸入密碼，操作已取消。")
            sys.exit(1)

        is_decrypt_mode = len(cli_file_paths) == 1 and cli_file_paths[0].lower().endswith(".encrypt")
        if is_decrypt_mode:
            decrypt_decompress_process(cli_file_paths[0], password, is_tty=is_interactive_tty)
        else:
            compress_encrypt_process(cli_file_paths, password, is_tty=is_interactive_tty)
        
        sys.exit(0)

    # 模式 2: GUI 模式 (無參數)
    else:
        window = TkinterDnD.Tk()
        window.title("檔案打包、壓縮與加解密工具")
        window.configure(bg="#f0f0f0")

        default_font = tkFont.Font(size=12)
        bold_font = tkFont.Font(size=12, weight="bold")

        tk.Label(window, text="輸入檔案:", font=bold_font, bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        drop_area_var = tk.StringVar(value="拖曳檔案至此或點擊瀏覽")
        drop_area = tk.Label(window, textvariable=drop_area_var, relief="groove", borderwidth=2, width=50, height=3,
                             font=default_font, bg="white", fg="#555555", wraplength=400, justify="center")
        drop_area.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        drop_area.drop_target_register(DND_FILES)
        drop_area.dnd_bind('<<Drop>>', drop_handler)
        drop_area.bind("<Button-1>", lambda event: browse_input_files())

        tk.Label(window, text="密碼:", font=bold_font, bg="#f0f0f0").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        password_entry = tk.Entry(window, width=50, show="*", font=default_font)
        password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        process_button = tk.Button(window, text="處理 (壓縮/加密 或 解密/解壓縮)", command=process_button_click, font=bold_font, bg="#4CAF50", fg="white")
        process_button.grid(row=2, column=0, columnspan=2, padx=10, pady=20, sticky="ew")

        window.grid_columnconfigure(1, weight=1)
        window.minsize(450, 250)
        window.mainloop()