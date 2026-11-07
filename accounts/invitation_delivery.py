"""Durable at-least-once invitation submission; SMTP acceptance is not inbox delivery."""
from datetime import timedelta
from urllib.parse import urlsplit
from uuid import uuid4
from django.conf import settings
from django.core.mail import send_mail
from django.db import connection
from django.db.models import Q, F
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from .models import InvitationDelivery


def eligible(now):
    return (Q(status='pending', next_attempt_at__lte=now)
            | Q(status='processing', lease_expires_at__lte=now))


def validate_configuration(base_url):
    parsed = urlsplit(base_url)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('A trusted HTTP(S) site origin is required.')
    for name, default in (('INVITATION_DELIVERY_LEASE_SECONDS', 120),
                          ('INVITATION_DELIVERY_MAX_ATTEMPTS', 5)):
        value = getattr(settings, name, default)
        if not isinstance(value, int) or value <= 0:
            raise ValueError('Invitation delivery limits must be positive integers.')


def claim(pk):
    now = timezone.now()
    owner = uuid4()
    seconds = getattr(settings, 'INVITATION_DELIVERY_LEASE_SECONDS', 120)
    changed = InvitationDelivery.objects.filter(pk=pk).filter(eligible(now)).update(
        status='processing', claim_id=owner, lease_expires_at=now + timedelta(seconds=seconds),
        attempts=F('attempts') + 1, last_attempt_at=now)
    return owner if changed else None


def finish(pk, owner, status, **fields):
    return InvitationDelivery.objects.filter(pk=pk, status='processing', claim_id=owner,
        lease_expires_at__gt=timezone.now()).update(status=status, claim_id=None,
        lease_expires_at=None, **fields)


def invalid_status(invitation):
    if invitation is None or invitation.accepted or not invitation.department.is_active:
        return 'cancelled'
    if not invitation.is_valid():
        return 'expired'
    return None


def process_one(pk, base_url):
    # Never submit from a caller's transaction (including ATOMIC_REQUESTS).
    if connection.in_atomic_block or not connection.get_autocommit():
        raise RuntimeError('Delivery processing requires autocommit.')
    validate_configuration(base_url)
    owner = claim(pk)
    if owner is None:
        return None
    delivery = InvitationDelivery.objects.select_related('invitation__department').get(pk=pk)
    invitation = delivery.invitation
    status = invalid_status(invitation)
    maximum = getattr(settings, 'INVITATION_DELIVERY_MAX_ATTEMPTS', 5)
    if status:
        return status if finish(pk, owner, status) else None
    if delivery.attempts > maximum:
        return 'failed' if finish(pk, owner, 'failed', last_error='Attempt limit reached.') else None
    body = render_to_string('accounts/invitation_email.txt', {
        'department': invitation.department, 'invitation': invitation,
        'acceptance_url': base_url.rstrip('/') + reverse('accept_invitation', args=[invitation.token])})
    # Recheck the claim and lifecycle just before network I/O; in-flight mail cannot be recalled.
    current = InvitationDelivery.objects.select_related('invitation__department').filter(
        pk=pk, status='processing', claim_id=owner, lease_expires_at__gt=timezone.now()).first()
    if current is None:
        return None
    status = invalid_status(current.invitation)
    if status:
        return status if finish(pk, owner, status) else None
    try:
        if send_mail('VeriMeet Officer invitation', body, settings.DEFAULT_FROM_EMAIL,
                     [invitation.email], fail_silently=False) != 1:
            raise RuntimeError('Backend did not report submission.')
    except Exception:
        # SMTP may already have accepted it. Retry the same token; never store raw errors.
        status = 'failed' if delivery.attempts >= maximum else 'pending'
        delay = min(3600, 60 * 2 ** min(delivery.attempts - 1, 6))
        changed = finish(pk, owner, status, last_error='Email submission failed or outcome uncertain.',
                         next_attempt_at=timezone.now() + timedelta(seconds=delay))
        return ('failed' if status == 'failed' else 'retried') if changed else None
    return 'submitted' if finish(pk, owner, 'submitted', submitted_at=timezone.now(), last_error='') else None
