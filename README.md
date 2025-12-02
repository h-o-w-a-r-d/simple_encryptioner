# Secure Packer (檔案打包加密工具)

**Secure Packer** 是一個基於 Python 開發的檔案安全工具，集成了 **打包 (Tar)**、**壓縮 (Gzip)** 與 **高強度加密 (Fernet/AES)** 功能。

它設計靈活，既支援直觀的圖形使用者介面 (GUI)，也支援命令列 (CLI) 操作，甚至可以直接將檔案拖曳到程式圖示上進行快速處理。

## ✨ 主要功能

*   **三合一處理**：自動執行 `打包 -> 壓縮 -> 加密` 流程，產出單一 `.encrypt` 檔案。
*   **高強度安全性**：
    *   使用 **Fernet** (對稱加密) 進行內容保護。
    *   使用 **PBKDF2HMAC-SHA256** (390,000 次迭代) 從密碼衍生金鑰，有效防禦暴力破解。
    *   每個檔案自動生成隨機 **Salt (鹽)**，確保即使相同密碼與內容，加密結果也不同。
*   **靈活的操作模式**：
    *   **GUI 模式**：支援拖放 (Drag & Drop) 檔案進視窗，介面簡潔。
    *   **CLI 模式**：在終端機執行，支援隱碼輸入。
    *   **拖曳執行 (Drop-to-EXE)**：若打包成 `.exe`，可直接將檔案拖曳到圖示上，會自動彈出密碼輸入視窗。
*   **安全解壓縮**：針對 Tar 格式進行路徑檢查 (防止 Zip Slip 攻擊)，支援 Python 3.12+ 的安全過濾器。

## 🛠️ 安裝需求

本專案使用 Python 3 開發。在執行之前，請確保已安裝以下相依套件：

```bash
pip install cryptography tkinterdnd2
```

*注意：`tkinter` 通常內建於 Python 安裝中。*

## 🚀 使用方法

### 1. 圖形介面模式 (GUI)
直接執行程式而不帶任何參數：

```bash
python simple_encryptioner.py
```
*   **加密**：將一個或多個檔案/資料夾拖入視窗（或點擊瀏覽），輸入密碼，點擊「處理」。
*   **解密**：將單個 `.encrypt` 檔案拖入視窗，輸入密碼，點擊「處理」。

### 2. 命令列模式 (CLI)
在終端機中指定檔案路徑：

```bash
# 加密多個檔案
python secure_packer.py file1.txt photo.jpg folder_name

# 解密檔案
python secure_packer.py backup_bundle.encrypt
```
程式會自動偵測終端機環境，並提示您輸入密碼（輸入時不會顯示字元）。

### 3. 編譯為執行檔 (可選)
若您希望將其打包為 `.exe` 以便在沒有 Python 的電腦上使用，或使用「拖曳到圖示」功能，建議使用 PyInstaller：

```bash
# --noconsole: 不顯示黑色終端機視窗 (適合 GUI 使用)
# --onefile: 打包成單一檔案
# --hidden-import: 確保 tkinterdnd2 被正確包含

pip install pyinstaller
pyinstaller --noconsole --onefile --hidden-import "tkinterdnd2" secure_packer.py
```
編譯後，您可以直接將檔案拖曳到 `secure_packer.exe` 上，程式會彈出獨立的密碼輸入視窗。

## 🔒 技術細節

*   **加密演算法**：AES-128 (CBC mode) via Fernet。
*   **金鑰衍生 (KDF)**：PBKDF2HMAC using SHA256。
*   **Salt**：`os.urandom(16)`，儲存於加密檔案的檔頭前 16 bytes。
*   **完整性驗證**：Fernet 內建 HMAC 簽章驗證，確保資料未被篡改。
*   **檔案結構**：
    ```text
    [Salt (16 bytes)] + [Fernet Encrypted Data ( Gzip( Tar( Files ) ) )]
    ```

## ⚠️ 免責聲明

本軟體按「原樣」提供，不提供任何形式的保證。使用者應自行承擔使用本軟體及其加密功能的風險。請務必牢記您的密碼，若密碼遺失，資料將無法復原。

## 授權條款

本專案採用 [MIT License](LICENSE) 授權。
Copyright (c) 2025 Howard Zhen
