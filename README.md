# litellm Supply Chain Attack Checker

> Shell script (macOS) · PowerShell script (Windows) · No dependencies required

[繁體中文版 →](./README.zh-TW.md)

---

## Background

On **2026-03-25**, the `litellm` PyPI package was compromised in a supply chain attack. An attacker gained access to the maintainer's PyPI account and published two malicious versions that were never part of any official GitHub release:

| Version | Trigger | Risk |
|---------|---------|------|
| `1.82.7` | `import litellm.proxy` | Credential theft |
| `1.82.8` | **Any Python startup** (via `litellm_init.pth`) | Credential theft |

The malicious code:
1. Collects SSH keys, environment variables, AWS/GCP/Azure/K8s credentials, crypto wallets, database passwords, shell history, and CI/CD configs
2. Encrypts the stolen data with AES-256-CBC + RSA-4096
3. Exfiltrates it via `curl POST` to `https://models.litellm.cloud/` — a lookalike domain registered by the attacker on 2026-03-23 (not the official `litellm.ai`)

> Reference: [BerriAI/litellm#24518](https://github.com/BerriAI/litellm/issues/24518)

---

## What this script checks

| Step | Check |
|------|-------|
| 1 | `pip` / `pip3` global installs |
| 2 | All Python `site-packages` directories |
| 3 | `conda` environments (if installed) |
| 4 | `pyenv` versions (if installed) |
| 5 | Project dependency files (`requirements.txt`, `pyproject.toml`, `Pipfile`, etc.) |
| 6 | Project virtual environments (`.venv` / `venv` / `env`) |
| 7 | `uv` tool (if installed) |
| 8 | `dist-info` / `egg-info` leftovers |
| 9 | **`litellm_init.pth`** — the v1.82.8 backdoor that triggers on any Python startup |
| 10 | Non-standard `.pth` files in `site-packages` |

---

## Usage

**macOS — double-click:**
1. Double-click `check_litellm.command` in Finder
2. If macOS blocks it: right-click → **Open** → **Open**

**macOS — terminal:**
```bash
chmod +x check_litellm.sh
./check_litellm.sh
```

**Windows — double-click:**
1. Double-click `check_litellm.bat` in File Explorer
2. If Windows SmartScreen appears: click **More info** → **Run anyway**

**Windows — PowerShell:**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\check_litellm.ps1
```

**Collect failed GitHub Actions logs into a folder:**
```bash
python3 collect_action_logs.py --limit 5 --output-dir action-logs
```

**Collect one specific run:**
```bash
python3 collect_action_logs.py --run-id 23534721081 --output-dir action-logs
```

This helper uses the `gh` CLI to find failed Actions runs, then writes:
- `action-logs/index.md`
- one subfolder per run
- `summary.md`
- `failed.log`
- one log file per failed job

If you are outside the repo, pass `--repo OWNER/REPO`.

---

## If infected

1. Remove litellm: `pip uninstall litellm -y`
2. Delete `litellm_init.pth` if found (check step 9 output)
3. **Rotate ALL credentials immediately:**
   - API keys (OpenAI, Anthropic, etc.)
   - SSH keys
   - AWS / GCP / Azure credentials
   - Database passwords
   - Any secrets stored in `.env` files or shell history
4. Review all connected services for unauthorized access

---

## Platform

| File | Platform | How to run |
|------|----------|------------|
| `check_litellm.command` | macOS | Double-click in Finder |
| `check_litellm.sh` | macOS | Terminal |
| `check_litellm.bat` | Windows | Double-click in File Explorer |
| `check_litellm.ps1` | Windows | PowerShell |

The macOS script uses `find` syntax. The Windows script uses PowerShell cmdlets (`Get-ChildItem`, `Select-String`). Both cover the same 10 check steps.
