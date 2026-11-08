"""Finite, at-least-once verification submission. No confirmation secrets persisted."""
from datetime import timedelta
from urllib.parse import urlsplit
from uuid import uuid4
from django.db import connection, transaction
from django.db.models import Q, F
from django.utils import timezone
from .models import User, VerificationEmailDelivery as Delivery

ACTIVE = ('pending', 'processing')


def cancel(query):
    return query.filter(status__in=ACTIVE).update(status='cancelled', claim_id=None, lease_expires_at=None)


def enqueue(address, signup=False):
    from allauth.account.models import EmailAddress
    with transaction.atomic():
        User.objects.filter(pk=address.user_id).update(username=F('username'))
        current = EmailAddress.objects.select_for_update().select_related('user').filter(pk=address.pk).first()
        if not current or current.verified or not current.user.is_active:
            return None
        if current.user_id != address.user_id or current.email != address.email:
            return None
        rows = Delivery.objects.filter(original_address_id=current.pk, status__in=ACTIVE)
        for row in rows:
            status = invalid_status(row)
            if status:
                Delivery.objects.filter(pk=row.pk, status__in=ACTIVE).update(
                    status=status, claim_id=None, lease_expires_at=None)
            else:
                return row
        return Delivery.objects.create(address=current, original_address_id=current.pk,
            original_user_id=current.user_id, recipient=current.email,
            session_version=current.user.session_version, signup=signup)


def eligible(now):
    return (Q(status='pending') & (Q(next_attempt_at__lte=now) | Q(expires_at__lte=now) | Q(attempts__gte=5))
            | Q(status='processing', lease_expires_at__lte=now))


def retire(pk, now):
    """Retire due/abandoned work without acquiring a sixth claim or stealing a live lease."""
    rows = Delivery.objects.filter(pk=pk).filter(eligible(now))
    if rows.filter(expires_at__lte=now).update(status='expired', claim_id=None, lease_expires_at=None):
        return 'expired'
    if rows.filter(expires_at__gt=now, attempts__gte=5).update(status='failed', claim_id=None,
            lease_expires_at=None, last_error='Attempt limit reached.'):
        return 'failed'
    return None


def validate_configuration(base_url):
    parsed = urlsplit(base_url)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ('', '/') or any(c.isspace() for c in base_url)):
        raise ValueError('Trusted HTTP(S) origin required')
    parsed.port
    from allauth.account import app_settings
    if not app_settings.EMAIL_CONFIRMATION_HMAC or app_settings.EMAIL_VERIFICATION_BY_CODE_ENABLED:
        raise ValueError('Verification processor requires existing HMAC link confirmation mode')


def claim(pk):
    now = timezone.now(); owner = uuid4()
    retire(pk, now)
    changed = Delivery.objects.filter(pk=pk, attempts__lt=5, expires_at__gt=now).filter(eligible(now)).update(status='processing',
        claim_id=owner, lease_expires_at=now+timedelta(seconds=120), attempts=F('attempts')+1,
        last_attempt_at=now)
    return owner if changed else None


def finish(pk, owner, status, **fields):
    return Delivery.objects.filter(pk=pk, status='processing', claim_id=owner,
        lease_expires_at__gt=timezone.now()).update(status=status, claim_id=None, lease_expires_at=None, **fields)


def invalid_status(delivery):
    from allauth.account.models import EmailAddress
    address = EmailAddress.objects.select_related('user').filter(pk=delivery.address_id).first()
    if (not address or address.pk != delivery.original_address_id or address.user_id != delivery.original_user_id
            or address.email != delivery.recipient or address.verified or not address.user.is_active
            or address.user.session_version != delivery.session_version):
        return 'cancelled'
    if delivery.expires_at <= timezone.now():
        return 'expired'
    return None


def render_message(delivery, base_url):
    from allauth.account.models import EmailConfirmationHMAC
    from allauth.account.adapter import get_adapter
    from allauth.core.context import request_context
    from django.test import RequestFactory
    from django.contrib.sites.shortcuts import get_current_site
    address = delivery.address
    request = RequestFactory().get(base_url.rstrip('/') + '/')
    with request_context(request):
        adapter = get_adapter(request)
        confirmation = EmailConfirmationHMAC.create(address)
        key = confirmation.key
        from django.urls import reverse
        url = base_url.rstrip('/') + reverse('account_confirm_email', args=[key])
        return adapter.render_mail('account/email/email_confirmation_signup' if delivery.signup else
            'account/email/email_confirmation', delivery.recipient, {
                'request': request, 'current_site': get_current_site(request), 'email': delivery.recipient,
                'user': address.user, 'key': key, 'activate_url': url})


def process_one(pk, base_url):
    if connection.in_atomic_block or not connection.get_autocommit():
        raise RuntimeError('Verification processing requires autocommit')
    validate_configuration(base_url)
    retired = retire(pk, timezone.now())
    if retired:
        return retired
    owner = claim(pk)
    if owner is None:
        return None
    delivery = Delivery.objects.select_related('address__user').get(pk=pk)
    status = invalid_status(delivery)
    if status:
        return status if finish(pk, owner, status) else None
    try:
        message = render_message(delivery, base_url)
        current = Delivery.objects.filter(pk=pk, status='processing', claim_id=owner,
            lease_expires_at__gt=timezone.now()).first()
        if current is None:
            return None
        status = invalid_status(current)
        if status:
            return status if finish(pk, owner, status) else None
        # Eligibility queries may take time. Check ownership/deadline again at the
        # submission boundary; an in-flight SMTP call still cannot be recalled.
        if not Delivery.objects.filter(pk=pk, status='processing', claim_id=owner,
                lease_expires_at__gt=timezone.now(), expires_at__gt=timezone.now()).exists():
            return None
        if message.send() != 1:
            raise RuntimeError('Backend did not report submission')
    except Exception:
        status = 'failed' if delivery.attempts >= 5 else 'pending'
        changed = finish(pk, owner, status, last_error='Email submission failed or outcome uncertain.',
            next_attempt_at=timezone.now()+timedelta(seconds=min(3600, 60*2**(delivery.attempts-1))))
        return ('failed' if status == 'failed' else 'retried') if changed else None
    return 'submitted' if finish(pk, owner, 'submitted', submitted_at=timezone.now(), last_error='') else None
