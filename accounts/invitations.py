"""Invitation continuation uses only server-generated local destinations."""
from django.urls import reverse
from .models import Invitation


def pending_invitation_url(request):
    token = request.session.get('pending_invite_token')
    if not isinstance(token, str) or len(token) > 64:
        return None
    invitation = Invitation.objects.filter(token=token, accepted=False, department__is_active=True).first()
    if invitation and invitation.is_valid():
        return reverse('accept_invitation', args=[invitation.token])
    return None
