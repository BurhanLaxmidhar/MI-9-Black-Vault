import os
import json
import base64
import time
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

VAULT_FILE = "blackvault.dat"
DECOY_FILE = "decoyvault.dat"

def file_exists(filename=VAULT_FILE):
    return os.path.exists(filename)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def create_vault(password: str, filename=VAULT_FILE, empty_data=None):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    if empty_data is None:
        empty_data = b'{"files": []}'
    encrypted = f.encrypt(empty_data)
    with open(filename, "wb") as vault:
        vault.write(salt + encrypted)

def try_unlock_vault(password: str, filename=VAULT_FILE):
    if not os.path.exists(filename):
        return None
    with open(filename, "rb") as vault:
        raw = vault.read()
        salt = raw[:16]
        encrypted = raw[16:]
        key = derive_key(password, salt)
        f = Fernet(key)
        try:
            decrypted = f.decrypt(encrypted)
            return decrypted
        except InvalidToken:
            return None

def load_vault(password: str, filename=VAULT_FILE):
    raw = try_unlock_vault(password, filename)
    if raw is not None:
        return json.loads(raw.decode())
    else:
        return None

def save_vault(password: str, vault_data: dict, filename=VAULT_FILE):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    data = json.dumps(vault_data).encode()
    encrypted = f.encrypt(data)
    with open(filename, "wb") as vault:
        vault.write(salt + encrypted)

def add_file_to_vault(password: str, vault_data: dict, filepath: str, filename=VAULT_FILE):
    with open(filepath, "rb") as file:
        file_bytes = file.read()
        encoded_data = base64.b64encode(file_bytes).decode()
        vault_data["files"].append({
            "name": os.path.basename(filepath),
            "data": encoded_data,
            "timestamp": int(time.time())
        })
    save_vault(password, vault_data, filename)

def extract_file_from_vault(file_entry: dict, output_path: str):
    file_bytes = base64.b64decode(file_entry["data"])
    with open(output_path, "wb") as file:
        file.write(file_bytes)

# Decoy vault functions

def create_decoy_vault(password: str, empty_data=None):
    create_vault(password, filename=DECOY_FILE, empty_data=empty_data)

def try_unlock_decoy_vault(password: str):
    return try_unlock_vault(password, filename=DECOY_FILE)
