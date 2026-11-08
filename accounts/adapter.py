from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.utils import get_next_redirect_url
from django.urls import reverse
from .invitations import pending_invitation, pending_invitation_url
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class OnboardingSocialAdapter(DefaultSocialAccountAdapter):
    def save_user(self, request, sociallogin, form=None):
        if (sociallogin.account.provider == 'google'
                and sociallogin.user._state.adding and not sociallogin.is_existing
                and sociallogin.state.get('process') != 'connect'):
            sociallogin.user.username_confirmation_required = True
        return super().save_user(request, sociallogin, form)


class InvitationAccountAdapter(DefaultAccountAdapter):
    def send_confirmation_mail(self, request, emailconfirmation, signup):
        from .verification_delivery import enqueue
        enqueue(emailconfirmation.email_address, signup=signup)

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
