from allauth.account.adapter import DefaultAccountAdapter
from .invitations import pending_invitation_url


class InvitationAccountAdapter(DefaultAccountAdapter):
    def post_login(self, request, user, **kwargs):
        destination = pending_invitation_url(request)
        if destination:
            kwargs['redirect_url'] = destination
        return super().post_login(request, user, **kwargs)

    def get_email_verification_redirect_url(self, email_address):
        return (pending_invitation_url(self.request)
                or super().get_email_verification_redirect_url(email_address))
