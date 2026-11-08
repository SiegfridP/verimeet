from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import OperationalError
from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from .models import User, Membership
from .account_status import active_admin, change_account_status


def authorize(request):
    user = User.objects.filter(pk=request.user.pk).first()
    if not user or not active_admin(user):
        raise PermissionDenied('Global Admin access required.')


@login_required
@require_http_methods(['GET'])
def account_directory(request):
    authorize(request)
    from django.db.models import Prefetch
    users = User.objects.only('id', 'username', 'email', 'is_active', 'is_admin', 'is_superuser').order_by('pk')
    users = users.prefetch_related(Prefetch('memberships', queryset=Membership.objects.filter(
        department__is_active=True).select_related('department')))
    return render(request, 'accounts/account_directory.html', {
        'page_obj': Paginator(users, 25).get_page(request.GET.get('page'))})


@login_required
@require_http_methods(['GET', 'POST'])
def account_status_confirmation(request, user_id):
    authorize(request)
    target = User.objects.filter(pk=user_id).first()
    from .views import is_global_admin
    if not target or target.pk == request.user.pk or is_global_admin(target):
        raise PermissionDenied('Account management is unavailable.')
    error = None
    if request.method == 'POST':
        try:
            state = signing.loads(request.POST.get('state', ''), salt='account-status', max_age=1800)
            if type(state) is not list or len(state) != 4:
                raise ValidationError('Explicit confirmation required. Refresh this page.')
            actor_id, target_id, original_active, session_version = state
            if (type(actor_id) is not int or type(target_id) is not int
                    or type(original_active) is not bool or type(session_version) is not int
                    or session_version < 0):
                raise ValidationError('Explicit confirmation required. Refresh this page.')
            if (not request.POST.get('confirm') or actor_id != request.user.pk or target_id != target.pk):
                raise ValidationError('Explicit confirmation required. Refresh this page.')
            change_account_status(request.user, target.pk, not original_active, original_active, session_version)
        except (signing.BadSignature, ValidationError):
            error = 'Account changed or confirmation missing. Refresh before trying again.'
        except OperationalError as exc:
            from django.db import connection
            from sqlite3 import SQLITE_BUSY, SQLITE_LOCKED
            code = getattr(exc.__cause__, 'sqlite_errorcode', None)
            busy = ((code & 255) in (SQLITE_BUSY, SQLITE_LOCKED) if code is not None else
                    str(exc).lower().partition(':')[0] in {'database is locked', 'database is busy',
                        'database table is locked', 'database schema is locked'})
            if connection.vendor != 'sqlite' or not busy:
                raise
            error = 'Account is busy. Refresh and retry.'
        else:
            messages.success(request, 'Account status request completed.')
            return redirect('account_directory')
    return render(request, 'accounts/account_status_confirmation.html', {
        'target': target, 'error': error, 'state': signing.dumps(
            [request.user.pk, target.pk, target.is_active, target.session_version], salt='account-status')},
        status=400 if error else 200)
