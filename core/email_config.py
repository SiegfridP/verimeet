"""Provider-neutral email configuration; errors never echo supplied values."""
import ipaddress
import math
import re
import unicodedata
from email.utils import formataddr, parseaddr
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.validators import validate_email


def validate_production_credential(name, value, *, django_secret=False, resend=False):
    """Reject malformed configuration without including supplied values in errors."""
    folded = re.sub(r'[^a-z0-9]', '', value.lower()) if isinstance(value, str) else ''
    invalid = (not isinstance(value, str) or not value.strip()
               or any(c.isspace() or unicodedata.category(c).startswith('C') for c in value)
               or any(marker in folded for marker in ('placeholder', 'changeme', 'replaceme', 'replacewith',
                                                       'inserthere',
                                                       'yoursecret', 'yourapikey', 'yourgoogle',
                                                       'yourclient', 'examplekey'))
               or folded in ('secret', 'password', 'test', 'example', 'todo', 'dummy'))
    if django_secret:
        invalid = invalid or len(value) < 50 or len(set(value)) < 5 or value.startswith('django-insecure-')
    if resend:
        invalid = invalid or re.fullmatch(r're_[A-Za-z0-9_-]{20,}', value) is None
    if invalid:
        raise ImproperlyConfigured('Invalid production credential: ' + name + '.') from None


def origin(value, production=False):
    try:
        p = urlsplit(value)
        if (not value or any(c.isspace() or ord(c) < 32 for c in value)
                or p.scheme not in (("https",) if production else ("http", "https"))
                or not p.hostname or p.username is not None or p.password is not None
                or p.path not in ("", "/") or "?" in value or "#" in value
                or "\\" in value or p.netloc.endswith(":")):
            raise ValueError
        p.port
        try:
            ipaddress.ip_address(p.hostname)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", p.hostname):
                raise ValueError
            if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in p.hostname.split(".")):
                raise ValueError
        return value.rstrip("/")
    except (ValueError, TypeError):
        raise ImproperlyConfigured("APPLICATION_ORIGIN must be a valid trusted origin (HTTPS in production), without credentials, path, query or fragment.") from None


def email_settings(env):
    def fail(name):
        raise ImproperlyConfigured("Invalid email configuration: " + name + ".") from None

    mode = env.get("DJANGO_ENV", "development")
    if mode not in ("development", "production"):
        fail("DJANGO_ENV must be development or production")
    production = mode == "production"
    def boolean(name, default):
        value = env.get(name, default).lower()
        if value not in ("true", "false"):
            fail(name + " must be true or false")
        return value == "true"
    try:
        port = int(env.get("EMAIL_PORT", "587"))
        timeout = float(env.get("EMAIL_TIMEOUT", "20"))
        if not 1 <= port <= 65535 or not math.isfinite(timeout) or not 0 < timeout < 120:
            raise ValueError
    except (ValueError, TypeError):
        fail("EMAIL_PORT or EMAIL_TIMEOUT (timeout must be positive and below the 120-second worker lease)")
    tls = boolean("EMAIL_USE_TLS", "true")
    ssl = boolean("EMAIL_USE_SSL", "false")
    if tls and ssl:
        fail("EMAIL_USE_TLS and EMAIL_USE_SSL are mutually exclusive")
    backend = env.get("EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend")
    host = env.get("EMAIL_HOST", "localhost")
    username = env.get("EMAIL_HOST_USER", "")
    password = env.get("EMAIL_HOST_PASSWORD", "")
    sender = env.get("DEFAULT_FROM_EMAIL", "VeriMeet <noreply@example.invalid>")
    display = env.get("EMAIL_FROM_NAME", "VeriMeet")
    try:
        _, address = parseaddr(sender)
    except (ValueError, TypeError):
        fail("DEFAULT_FROM_EMAIL must contain a valid sender address")
    try:
        validate_email(address)
    except ValidationError:
        fail("DEFAULT_FROM_EMAIL must contain a valid sender address")
    if any(ord(c) < 32 or ord(c) == 127 for c in sender + display) or not display.strip():
        fail("sender identity")
    canonical = env.get("APPLICATION_ORIGIN", "")
    https_backend = backend == 'core.resend_backend.EmailBackend'
    if production and https_backend:
        validate_production_credential('RESEND_API_KEY', env.get('RESEND_API_KEY', ''), resend=True)
        if address.endswith(('.invalid', 'example.com')):
            fail('HTTPS email requires API key and authorized sender')
    if production and not https_backend:
        if backend != "django.core.mail.backends.smtp.EmailBackend":
            fail("production requires the SMTP backend")
        if not (tls or ssl):
            fail("production requires SMTP TLS or SSL")
        def placeholder(value):
            return not value.strip() or "YOUR_" in value.upper() or "example." in value.lower() or value.lower().endswith(".invalid")
        if (any(c.isspace() or ord(c) < 32 for c in host)
                or any(c in host for c in '/@?#\\')
                or any(ord(c) < 32 or ord(c) == 127 for c in username + password)):
            fail("SMTP host or credentials contain invalid characters")
        if any(placeholder(v) for v in (host, username, password, address)) or host.lower() == "localhost":
            fail("production requires non-placeholder SMTP host, credentials and sender")
    canonical = origin(canonical, production) if canonical or production else ""
    mailer = {"BACKEND": backend}
    if backend == "django.core.mail.backends.smtp.EmailBackend":
        mailer["OPTIONS"] = dict(host=host, port=port, username=username, password=password,
                                 use_tls=tls, use_ssl=ssl, timeout=timeout)
    return {"RESEND_API_KEY": env.get('RESEND_API_KEY', ''), "RESEND_TIMEOUT": timeout,
            "EMAIL_PRODUCTION": production, "APPLICATION_ORIGIN": canonical,
            "DEFAULT_FROM_EMAIL": formataddr((display, address)), "MAILERS": {"default": mailer}}


def worker_origin(base_url):
    from django.conf import settings
    production = getattr(settings, "EMAIL_PRODUCTION", False)
    supplied = origin(base_url, production)
    canonical = getattr(settings, "APPLICATION_ORIGIN", "")
    if canonical:
        canonical = origin(canonical, production)
        if supplied != canonical:
            raise ImproperlyConfigured("Worker base-url must match APPLICATION_ORIGIN.")
        return canonical
    if production:
        raise ImproperlyConfigured("APPLICATION_ORIGIN is required in production.")
    return supplied
