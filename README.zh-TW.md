# litellm 供應鏈攻擊檢查腳本

> Shell 腳本（macOS）· PowerShell 腳本（Windows）· 無需任何依賴套件

[English Version →](./README.md)

---

## 背景

**2026-03-25**，PyPI 上的 `litellm` 套件遭受供應鏈攻擊。攻擊者取得了維護者的 PyPI 帳號存取權，並發佈了兩個從未經過官方 GitHub CI/CD 流程的惡意版本：

| 版本 | 觸發條件 | 風險 |
|------|---------|------|
| `1.82.7` | 執行 `import litellm.proxy` | 憑證竊取 |
| `1.82.8` | **任何 Python 啟動**（透過 `litellm_init.pth`） | 憑證竊取 |

惡意程式碼會：
1. 蒐集 SSH 金鑰、環境變數、AWS/GCP/Azure/K8s 憑證、加密錢包、資料庫密碼、Shell 歷史紀錄、CI/CD 設定檔
2. 使用 AES-256-CBC + RSA-4096 加密竊取的資料
3. 透過 `curl POST` 將資料傳送至 `https://models.litellm.cloud/`——攻擊者在 2026-03-23 才剛註冊的仿冒域名（非官方的 `litellm.ai`）

> 參考資料：[BerriAI/litellm#24518](https://github.com/BerriAI/litellm/issues/24518)

---

## 腳本檢查範圍

| 步驟 | 檢查項目 |
|------|---------|
| 1 | `pip` / `pip3` 全域安裝 |
| 2 | 所有 Python `site-packages` 目錄 |
| 3 | `conda` 環境（若有安裝） |
| 4 | `pyenv` 各版本（若有安裝） |
| 5 | 專案依賴檔案（`requirements.txt`、`pyproject.toml`、`Pipfile` 等） |
| 6 | 專案虛擬環境（`.venv` / `venv` / `env`） |
| 7 | `uv` 工具（若有安裝） |
| 8 | `dist-info` / `egg-info` 殘留檔案 |
| 9 | **`litellm_init.pth`**——v1.82.8 後門，只要 Python 啟動即觸發，無需任何 import |
| 10 | `site-packages` 中非標準的 `.pth` 檔案 |

---

## 使用方式

**macOS — 雙擊執行：**
1. 在 Finder 中雙擊 `check_litellm.command`
2. 若 macOS 阻擋：右鍵 → **開啟** → **開啟**

**macOS — 終端機：**
```bash
chmod +x check_litellm.sh
./check_litellm.sh
```

**Windows — 雙擊執行：**
1. 在檔案總管中雙擊 `check_litellm.bat`
2. 若出現 Windows SmartScreen 警告：點選**更多資訊** → **仍要執行**

**Windows — PowerShell：**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\check_litellm.ps1
```

**把失敗的 GitHub Actions log 收集到同一個資料夾：**
```bash
python3 collect_action_logs.py --limit 5 --output-dir action-logs
```

**只抓某一次 run：**
```bash
python3 collect_action_logs.py --run-id 23534721081 --output-dir action-logs
```

這個輔助腳本會透過 `gh` CLI 找出失敗的 Actions run，並輸出：
- `action-logs/index.md`
- 每個 run 一個子資料夾
- `summary.md`
- `failed.log`
- 每個失敗 job 各自的 log 檔

如果你不在 repo 目錄內執行，請補上 `--repo OWNER/REPO`。

---

## 若發現感染

1. 移除套件：`pip uninstall litellm -y`
2. 若在步驟 9 找到 `litellm_init.pth`，立即刪除
3. **立即輪替所有憑證：**
   - API 金鑰（OpenAI、Anthropic 等）
   - SSH 金鑰
   - AWS / GCP / Azure 憑證
   - 資料庫密碼
   - 任何存在於 `.env` 檔案或 Shell 歷史紀錄中的機密
4. 檢查所有已連接服務是否有未授權存取紀錄

---

## 適用平台

| 檔案 | 平台 | 執行方式 |
|------|------|---------|
| `check_litellm.command` | macOS | 在 Finder 雙擊 |
| `check_litellm.sh` | macOS | 終端機 |
| `check_litellm.bat` | Windows | 在檔案總管雙擊 |
| `check_litellm.ps1` | Windows | PowerShell |

macOS 腳本使用 `find` 語法；Windows 腳本使用 PowerShell cmdlet（`Get-ChildItem`、`Select-String`）。兩者涵蓋相同的 10 個檢查步驟。
