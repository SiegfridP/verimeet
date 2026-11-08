from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from .signatures import complete
from django.utils.functional import cached_property


class OnboardingMiddleware:
    @cached_property
    def allowed_views(self):
        # Identity checks cover unnamed/namespaced routes without trusting names.
        from allauth.account import views as account
        from allauth.socialaccount import views as social
        from allauth.socialaccount.providers.google import views as google
        from . import views
        from meetings.views import verify_individual_signature
        return {
            views.onboarding, views.signature_preview, verify_individual_signature,
            account.login, account.logout, account.signup, account.email,
            account.confirm_email, account.email_verification_sent,
            account.account_inactive, account.reauthenticate, account.confirm_login_code,
            account.password_reset, account.password_reset_done,
            account.password_reset_from_key, account.password_reset_from_key_done,
            social.signup, social.login_error, social.login_cancelled,
            google.oauth2_login, google.oauth2_callback, google.login_by_token,
        }

    def __init__(self, get_response):
        self.get_response = get_response

    def process_view(self, request, view, args, kwargs):
        if (request.user.is_authenticated and view not in self.allowed_views
                and not complete(request.user)):
            if request.method not in ('GET', 'HEAD'):
                return HttpResponseForbidden('Complete account onboarding before submitting this action.')
            from .views import accept_invitation
            if view is accept_invitation:
                from .models import Invitation
                from allauth.account.utils import has_verified_email
                invitation = Invitation.objects.filter(token=kwargs.get('token'), accepted=False,
                                                       department__is_active=True).first()
                if invitation and invitation.is_valid() and has_verified_email(request.user, invitation.email):
                    request.session['onboarding_invitation'] = [invitation.token, request.user.pk]
            return redirect('onboarding')

    def __call__(self, request):
        from django.conf import settings
        from posixpath import normpath
        # Runs before URL resolution, including unnamed static and missing routes.
        media_path = normpath(request.path.replace('\\', '/')).casefold()
        # Windows treats trailing dots/spaces in path components as aliases.
        media_path = '/'.join(part.rstrip(' .') for part in media_path.split('/'))
        private_prefix = settings.MEDIA_URL.rstrip('/').casefold() + '/signatures'
        if media_path == private_prefix or media_path.startswith(private_prefix + '/'):
            return HttpResponseForbidden('Private signature asset.')
        media_prefix = settings.MEDIA_URL.rstrip('/') + '/'
        if request.path.casefold().startswith(media_prefix.casefold()):
            from pathlib import Path
            try:
                # Resolve filesystem aliases too (symlinks and Windows short names).
                root = Path(settings.MEDIA_ROOT).resolve()
                target = (root / request.path[len(media_prefix):].replace('\\', '/')).resolve()
                legacy = (root / 'signatures').resolve()
                if target == legacy or legacy in target.parents:
                    return HttpResponseForbidden('Private signature asset.')
            except (OSError, ValueError, RuntimeError):
                return HttpResponseForbidden('Media path unavailable.')
        return self.get_response(request)
