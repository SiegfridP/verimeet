import hmac
import hashlib
import time
from django.conf import settings
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

def generate_ecdsa_keypair():
    """Generates a new SECP256R1 keypair and returns them as PEM strings."""
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

def sign_document_data(private_key_pem, document_text):
    """Signs the document text using the user's private key."""
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