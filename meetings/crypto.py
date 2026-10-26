import hmac
import hashlib
import os
from django.conf import settings
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet, InvalidToken



# Encryption helpers for private keys using Fernet and SIGNING_KEY_ENCRYPTION_KEY from the environment

def _get_fernet() -> Fernet:
    """Create a Fernet instance from SIGNING_KEY_ENCRYPTION_KEY.
    Raises RuntimeError if the key is missing, empty, or invalid.
    """
    key = os.getenv('SIGNING_KEY_ENCRYPTION_KEY')
    if not key:
        raise RuntimeError('SIGNING_KEY_ENCRYPTION_KEY is not set or empty in environment')
    try:
        return Fernet(key.encode('utf-8'))
    except Exception as exc:
        raise RuntimeError('Invalid SIGNING_KEY_ENCRYPTION_KEY configuration') from exc

def encrypt_private_key(plain_pem: str) -> str:
    """Encrypt a PEM‑encoded private key and return the token as a string."""
    f = _get_fernet()
    token = f.encrypt(plain_pem.encode('utf-8'))
    return token.decode('utf-8')

def decrypt_private_key(token: str) -> str:
    """Decrypt a Fernet token back to the PEM string.
    Raises RuntimeError on failure without exposing sensitive data.
    """
    f = _get_fernet()
    try:
        plain = f.decrypt(token.encode('utf-8'))
        return plain.decode('utf-8')
    except (InvalidToken, TypeError, ValueError, UnicodeError) as exc:
        raise RuntimeError('Failed to decrypt private key: invalid or malformed token') from exc
    except Exception as exc:
        raise RuntimeError('Failed to decrypt private key') from exc

def generate_ecdsa_keypair():
    """Generates a new SECP256R1 keypair and returns PEM strings for private and public keys."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return priv_pem, pub_pem

def sign_document_data(encrypted_private_key: str, document_text: str) -> str:
    """Signs the document text using the user's decrypted private key."""
    try:
        private_key_pem = decrypt_private_key(encrypted_private_key)
    except Exception as exc:
        raise RuntimeError("Failed to decrypt private key for signing.") from exc

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    signature = private_key.sign(
        document_text.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )
    return signature.hex()



def generate_hmac_qr_token(meeting_id, timestamp):
    """Generates a secure HMAC-SHA256 token for the QR code."""
    message = f"{meeting_id}:{timestamp}".encode('utf-8')
    # Using Django's SECRET_KEY as the server's master key
    secret = settings.SECRET_KEY.encode('utf-8')
    return hmac.new(secret, message, hashlib.sha256).hexdigest()