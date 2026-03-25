---
name: litellm-infection-checker
description: Use this skill whenever the user wants to check a Mac, Windows PC, Python environment, project, repository, or workstation for a malicious LiteLLM installation, suspicious `litellm_init.pth`, or the compromised `litellm` versions `1.82.7` or `1.82.8`. Also use it when the user mentions the LiteLLM supply-chain attack, asks to "scan this machine", "check whether I got hit", "use this repo to check for LiteLLM compromise", "幫我檢查有沒有 litellm 惡意版本", "掃一下這台電腦有沒有中 LiteLLM", or similar infection-triage requests. Prefer this skill even when the user does not explicitly mention the repo, because the repo scripts already implement the correct LiteLLM-specific checks.
---

# LiteLLM infection checker

Help the user determine whether their machine, project, or test fixture shows signs of the compromised `litellm` package.

## Core behavior

1. Identify the requested target scope.
   - If the user names a directory, repository, fixture, project, or virtual environment, use that scope.
   - If they do not name a scope, use the most relevant current workspace or repository instead of claiming you scanned an entire machine by default.

2. Locate the repository scanner before doing anything else.
   - Prefer a workspace that contains `check_litellm.sh` and/or `check_litellm.ps1`.
   - Read `README.md` or `README.zh-TW.md` if you need confirmation about supported checks or remediation steps.
   - If the repo is missing, say so clearly and ask for the repo path or for the user to place the checker repo in the workspace.

3. Choose the platform-appropriate script.
   - On macOS or other environments where Bash is available, use `check_litellm.sh`.
   - On Windows or PowerShell environments, use `check_litellm.ps1`.
   - If the user asks about Windows while you are not in a Windows environment, do not pretend you executed the scan. Give the exact command the user should run there.

4. Prefer a scoped scan when possible.
   - If the user gives a target path, set `LITELLM_SCAN_ROOT` to that path.
   - This is especially important for fixture-based validation, targeted project scans, and cases where scanning the whole home directory would be noisy or unnecessary.
   - If you use `LITELLM_SCAN_ROOT`, explicitly say the result is limited to that scope.

5. Prefer the repo's existing scripts over inventing a new checker.
   - The repo already knows how to check pip installs, site-packages, conda, pyenv, dependency files, project virtualenvs, `uv`, leftover `dist-info` or `egg-info`, `litellm_init.pth`, and unexpected `.pth` files.
   - Only provide manual guidance when you cannot run the platform-appropriate script.

6. Interpret the result conservatively.
   - **Infected**: any confirmed `litellm` version `1.82.7` or `1.82.8`, or any `litellm_init.pth` hit.
   - **Risky**: version ranges that may include those malicious versions, or `litellm` is present but not clearly one of the known bad versions.
   - **Clean**: no confirmed malicious versions and no `litellm_init.pth`, within the scope that was actually scanned.

## Recommended commands

### macOS / Bash

If you are running the scan yourself, prefer:

```bash
cd /path/to/litellm-supply-chain-checker
LITELLM_SCAN_ROOT="/path/to/target" bash ./check_litellm.sh
```

If the user wants the default broader scan for their account, omit `LITELLM_SCAN_ROOT` and say that the scan is broader.

### Windows / PowerShell

If you are running on Windows, prefer:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$env:LITELLM_SCAN_ROOT = "C:\path\to\target"
.\check_litellm.ps1
```

If the user wants the default broader scan for their account, omit `LITELLM_SCAN_ROOT` and say that the scan is broader.

## Report structure

Always use this structure:

```markdown
# LiteLLM scan result
## Verdict
- Clean / Risky / Infected

## How I checked
- Which repo script was used
- Whether the scan was scoped with `LITELLM_SCAN_ROOT`
- What path or environment was examined

## Key findings
- Exact evidence that drove the verdict
- Mention `litellm_init.pth` explicitly if it was found
- Mention whether the issue is a confirmed hit or only a risky range/reference

## Recommended next actions
- If infected: uninstall `litellm`, delete `litellm_init.pth`, rotate credentials, review connected services
- If risky: verify versions immediately and clean up suspicious references
- If clean: state that no confirmed compromise was found in the scanned scope

## Raw evidence
- Quote the most important output lines
```

## Guardrails

- Never claim a full-machine scan if you only checked a scoped directory.
- Never say the system is safe beyond the path or environment that was actually scanned.
- Do not hide uncertainty. If you could only inspect files or provide commands, say that explicitly.
- If the user is on the wrong platform for execution, provide the correct repo command for their platform rather than improvising.
- Match the user's language. If the user writes in Traditional Chinese, respond in Traditional Chinese.

## Examples

**Example 1**

Input: `用這個 repo 幫我掃一下 tests/fixtures/infected，看有沒有 LiteLLM 惡意版本。`

Behavior: use the repo-local Bash script, scope the scan to `tests/fixtures/infected`, report an **Infected** verdict, and quote the malicious version evidence.

**Example 2**

Input: `I think my teammate's Windows box got hit by the LiteLLM supply-chain attack. Tell me exactly what to run from this repo.`

Behavior: provide the PowerShell command sequence from this repo, mention `check_litellm.ps1`, and explain that `litellm_init.pth` is a critical compromise indicator.
