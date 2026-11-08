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
    def render_mail(self, template_prefix, email, context, headers=None):
        from django.conf import settings
        from django.core.exceptions import ImproperlyConfigured
        from django.http.request import validate_host
        from urllib.parse import urlsplit
        import re
        import unicodedata
        from core.email_config import origin

        variables = {
            'account/email/email_confirmation_signup': 'activate_url',
            'account/email/email_confirmation': 'activate_url',
            'account/email/password_reset_key': 'password_reset_url',
            'account/email/unknown_account': 'signup_url',
            'account/email/account_already_exists': 'password_reset_url',
        }
        name = variables.get(template_prefix)
        if name is not None:
            canonical = getattr(settings, 'APPLICATION_ORIGIN', '')
            if canonical or getattr(settings, 'EMAIL_PRODUCTION', False):
                canonical = origin(canonical, getattr(settings, 'EMAIL_PRODUCTION', False))
            try:
                source = context[name]
                if (not isinstance(source, str) or not source
                        or any(c.isspace() or unicodedata.category(c).startswith('C') for c in source)
                        or '#' in source or "\\" in source
                        or re.search(r'%(?![0-9a-fA-F]{2})', source)
                        or re.search(r'%(?:0[0-9a-f]|1[0-9a-f]|7f)', source, re.I)):
                    raise ValueError
                parts = urlsplit(source)
                # Reuse strict authority validation, allowing HTTP source links even
                # when production rewrites them to canonical HTTPS.
                origin(parts.scheme + '://' + parts.netloc)
                if parts.port is not None and not 1 <= parts.port <= 65535:
                    raise ValueError
                trusted = [host for host in settings.ALLOWED_HOSTS if host != '*']
                if canonical:
                    trusted.append(urlsplit(canonical).hostname)
                if not validate_host(parts.hostname.lower(), trusted):
                    raise ValueError
                if canonical:
                    # Slice the original suffix to preserve even empty query markers,
                    # escaping and token bytes; never parse/re-encode the query.
                    authority = re.match(r'https?://[^/?#]+', source, re.I)
                    if authority is None:
                        raise ValueError
                    context = dict(context)
                    context[name] = canonical + source[authority.end():]
            except (KeyError, ValueError, TypeError, ImproperlyConfigured):
                raise ImproperlyConfigured('Invalid application URL in supported account email.') from None
        return super().render_mail(template_prefix, email, context, headers=headers)

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
