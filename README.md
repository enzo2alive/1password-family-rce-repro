# 1Password Families CSV Injection RCE Repro

Python script to repro CSV injection in vault export, chaining to RCE on import (server blob lag skips escape). Impacts family/team shares—multi-user exec.

## Setup
- `pip install -r requirements.txt`
- Hardcode creds in main.py (main + dummy emails/keys).
- Swap VAULT_ID from API (step 3).
- Token mode: Update headers with Bearer YOUR_TOKEN.

## Usage
`python main.py --rce_cmd "calc.exe"`

## Flow
1. Auth main, create vault/item with formula injection.
2. Export CSV (lag skips escape).
3. Sim import—RCE triggers on spreadsheet open.
4. Dummy verifies share, scales to family leak/edit.

## Expected
Calc pops on import, vault field hacked. Screenshots pre/post.
