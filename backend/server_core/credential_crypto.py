import os
import threading

from cryptography.fernet import Fernet, InvalidToken

from backend.server_core import config_core

_PREFIX = "fernet:v1:"
_lock = threading.Lock()
_fernet: Fernet | None = None


def _key_path() -> str:
    config_dir = os.path.join(config_core.default_data_dir(), "config")
    os.makedirs(config_dir, exist_ok=True)
    return os.path.join(config_dir, "cred_key")


def _load_or_create_key() -> bytes:
    env_key = os.environ.get("NYXSTRIKE_CRED_ENC_KEY", "").strip()
    if env_key:
        return env_key.encode()

    path = _key_path()
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read().strip()

    key = Fernet.generate_key()
    with open(path, "wb") as fh:
        fh.write(key)
    os.chmod(path, 0o600)
    return key


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        with _lock:
            if _fernet is None:
                _fernet = Fernet(_load_or_create_key())
    return _fernet


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return plaintext
    return _PREFIX + _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(value: str) -> str:
    if not value or not value.startswith(_PREFIX):
        return value
    try:
        return _get_fernet().decrypt(value[len(_PREFIX):].encode()).decode()
    except InvalidToken:
        return value
