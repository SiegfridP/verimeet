"""Invitation continuation uses only server-generated local destinations."""
from django.urls import reverse
from .models import Invitation


DISCOVERY_LIMIT = 20


def recipient_invitations(user, *, token=None):
    """Bounded, deterministic discovery; a token only narrows verified ownership."""
    from allauth.account.models import EmailAddress
    from django.db.models.functions import Lower
    from django.utils import timezone
    if not user.is_authenticated or not user.is_active:
        return Invitation.objects.none()
    addresses = EmailAddress.objects.filter(user=user, verified=True).annotate(
        normalized_email=Lower('email')).values('normalized_email')
    invitations = Invitation.objects.annotate(recipient_email=Lower('email')).filter(
        recipient_email__in=addresses, accepted=False, expires_at__gt=timezone.now(),
        department__is_active=True).select_related('department').order_by('-created_at', '-pk')
    if token is not None:
        invitations = invitations.filter(token=token)
    return invitations[:DISCOVERY_LIMIT]


def dashboard_invitations(request):
    """Include an eligible continuation beyond the first page without changing session intent."""
    invitations = list(recipient_invitations(request.user))
    token = request.session.get('pending_invite_token')
    if (isinstance(token, str) and 0 < len(token) <= 64
            and all(invitation.token != token for invitation in invitations)):
        continuation = next(iter(recipient_invitations(request.user, token=token)), None)
        if continuation:
            invitations.append(continuation)
    return invitations


def clear_pending_invitation(request):
    request.session.pop('pending_invite_token', None)
    request.session.pop('invite_verification_intent', None)


def pending_invitation(request):
    token = request.session.get('pending_invite_token')
    if not isinstance(token, str) or not token or len(token) > 64:
        clear_pending_invitation(request)
        return None
    invitation = Invitation.objects.filter(token=token, accepted=False, department__is_active=True).first()
    if invitation and invitation.is_valid():
        return invitation
    clear_pending_invitation(request)
    return None


def pending_invitation_url(request):
    invitation = pending_invitation(request)
    if invitation:
        return reverse('accept_invitation', args=[invitation.token])
    return None
