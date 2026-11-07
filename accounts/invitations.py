"""Invitation continuation uses only server-generated local destinations."""
from django.urls import reverse
from .models import Invitation


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
