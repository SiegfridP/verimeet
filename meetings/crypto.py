import hmac
import hashlib
import os
import secrets
import time
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
    """Signs the document text using the user's decrypted private key.

    The cryptography library applies SHA-256 internally as part of
    ec.ECDSA(hashes.SHA256()) before producing the ECDSA signature.

    Returns:
        Hex-encoded DER ECDSA signature string.
    """
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


def verify_document_signature(public_key_pem: str, document_text: str, signature_hex: str) -> bool:
    """Verifies an ECDSA signature produced by sign_document_data().

    Uses the same algorithm (ec.ECDSA(hashes.SHA256())) and encoding
    (hex-encoded DER) as the signing function so that signatures produced
    by the existing sign_meeting workflow can be verified without
    any re-encoding step.

    Args:
        public_key_pem:  PEM-encoded ECDSA public key (from User.public_key).
        document_text:   The exact canonical payload that was passed to
                         sign_document_data() at signing time.
        signature_hex:   The hex string stored in
                         Attendance.cryptographic_signature.

    Returns:
        True  – signature is cryptographically valid for the given key and payload.
        False – signature is invalid, tampered, or does not match the payload/key.

    Never raises on bad input: malformed keys, malformed hex, wrong-curve keys,
    and invalid signatures all return False.
    """
    if not public_key_pem or not document_text or not signature_hex:
        return False

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    except Exception:
        return False

    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False

    try:
        public_key.verify(
            signature_bytes,
            document_text.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False


def generate_qr_session_token() -> str:
    """Generates a cryptographically secure, unpredictable URL-safe token for a QR session."""
    return secrets.token_urlsafe(32)


def generate_hmac_qr_token(meeting_id, timestamp, purpose: str = None) -> str:
    """Generates a secure HMAC-SHA256 token for the QR code.

    If purpose is provided, binds the purpose into the HMAC message for
    cryptographic purpose separation. Otherwise preserves legacy Batch 05 format.
    """
    if purpose:
        message = f"{meeting_id}:{timestamp}:{purpose}".encode('utf-8')
    else:
        message = f"{meeting_id}:{timestamp}".encode('utf-8')
    secret = settings.SECRET_KEY.encode('utf-8')
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_hmac_qr_token(meeting_id, timestamp, received_sig, purpose: str = None, max_age: int = 3600) -> bool:
    """Verifies an HMAC QR token with constant-time comparison, expiration, and purpose binding.

    Returns True if the signature matches and timestamp is within the allowed window.
    """
    if not timestamp or not received_sig:
        return False
    try:
        ts = int(timestamp)
        now = int(time.time())
        token_age = now - ts
        if token_age < 0 or token_age > max_age:
            return False
        expected_sig = generate_hmac_qr_token(meeting_id, timestamp, purpose=purpose)
        return hmac.compare_digest(expected_sig, received_sig)
    except (ValueError, TypeError):
        return False


# Batch 08 — Separate Document Verification QR helpers

def generate_verification_token() -> str:
    """Generates an opaque, cryptographically secure 256-bit URL-safe token for public document verification."""
    return secrets.token_urlsafe(32)


def hash_verification_token(raw_token: str) -> str:
    """Returns the SHA-256 hex digest of a verification token for secure database lookup."""
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()


def encrypt_verification_token(raw_token: str) -> str:
    """Encrypts a verification token at rest using Fernet for persistent AP retrieval."""
    f = _get_fernet()
    token_bytes = f.encrypt(raw_token.encode('utf-8'))
    return token_bytes.decode('utf-8')


def decrypt_verification_token(encrypted_token: str) -> str:
    """Decrypts a stored verification token back to plaintext for AP QR code rendering."""
    f = _get_fernet()
    try:
        plain_bytes = f.decrypt(encrypted_token.encode('utf-8'))
        return plain_bytes.decode('utf-8')
    except Exception as exc:
        raise RuntimeError("Failed to decrypt verification token") from exc


def build_canonical_signing_payload(meeting_id, department_id, title: str, minutes_content: str, annotation: str = '') -> str:
    """Constructs the canonical meeting-bound signing payload string."""
    minutes = minutes_content or ''
    ann = annotation or ''
    return (
        f"meeting_id:{meeting_id}\n"
        f"department_id:{department_id}\n"
        f"title:{title}\n"
        f"{minutes}\n"
        f"---ANNOTATION---\n"
        f"{ann}"
    )


def build_legacy_signing_payload(minutes_content: str, annotation: str = '') -> str:
    """Constructs the legacy unbound signing payload string (Batch 05 format)."""
    minutes = minutes_content or ''
    ann = annotation or ''
    return f"{minutes}\n---ANNOTATION---\n{ann}"


def verify_attendance_signature(public_key_pem: str, meeting_id, department_id, title: str, minutes_content: str, annotation: str, signature_hex: str) -> dict:
    """Verifies a single attendee signature against canonical and legacy payload formats.

    Returns:
        dict: {
            'valid': bool,
            'format': 'canonical' | 'legacy' | None,
            'is_legacy': bool,
            'meeting_bound': bool,
            'reason': str or None,
        }
    """
    if not public_key_pem or not signature_hex:
        return {
            'valid': False,
            'format': None,
            'is_legacy': False,
            'meeting_bound': False,
            'reason': 'Missing public key or signature on record.',
        }

    # 1. Canonical meeting-bound check
    canonical_payload = build_canonical_signing_payload(meeting_id, department_id, title, minutes_content, annotation)
    if verify_document_signature(public_key_pem, canonical_payload, signature_hex):
        return {
            'valid': True,
            'format': 'canonical',
            'is_legacy': False,
            'meeting_bound': True,
            'reason': None,
        }

    # 2. Legacy fallback check
    legacy_payload = build_legacy_signing_payload(minutes_content, annotation)
    if verify_document_signature(public_key_pem, legacy_payload, signature_hex):
        return {
            'valid': True,
            'format': 'legacy',
            'is_legacy': True,
            'meeting_bound': False,
            'reason': 'Verified using legacy format without meeting ID, department, or title binding.',
        }

    # 3. Verification failed for both
    return {
        'valid': False,
        'format': None,
        'is_legacy': False,
        'meeting_bound': False,
        'reason': 'Signature verification failed for both canonical and legacy payload formats.',
    }
