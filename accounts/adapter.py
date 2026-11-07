from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.utils import get_next_redirect_url
from django.urls import reverse
from .invitations import pending_invitation, pending_invitation_url


class InvitationAccountAdapter(DefaultAccountAdapter):
    def post_login(self, request, user, **kwargs):
        destination = pending_invitation_url(request)
        # Allauth carries explicit next through password login, signup and OAuth state.
        target = kwargs.get('redirect_url') or get_next_redirect_url(request)
        if destination and target == destination:
            request.session['invite_verification_intent'] = [request.session['pending_invite_token'], user.pk]
        else:
            request.session.pop('invite_verification_intent', None)
        return super().post_login(request, user, **kwargs)

    def get_email_verification_redirect_url(self, email_address):
        invitation = pending_invitation(self.request)
        intent = self.request.session.get('invite_verification_intent')
        if (invitation and email_address
                and self.request.user.is_authenticated
                and self.request.user.pk == email_address.user_id
                and intent == [invitation.token, email_address.user_id]
                # Match Allauth EmailAddress.objects.get_for_user normalization.
                and email_address.email == invitation.email.lower()):
            return reverse('accept_invitation', args=[invitation.token])
        return super().get_email_verification_redirect_url(email_address)
