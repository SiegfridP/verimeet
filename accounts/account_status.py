"""Global status policy shared by application and Django Admin."""
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction, models
from django.db.models import F
from .models import User
from .audit import record


def lock_accounts(ids):
    # Same order for status and Admin privilege edits; SQLite needs a write guard.
    for pk in sorted(set(ids)):
        User.objects.filter(pk=pk).update(username=F('username'))


def active_admin(user):
    from .views import is_global_admin
    return user.is_authenticated and user.is_active and is_global_admin(user)


def change_account_status(actor, target_id, active, expected_active=None, expected_version=None):
    if (not actor.is_authenticated or not actor.pk or type(target_id) is not int
            or type(active) is not bool):
        raise PermissionDenied('Account management is unavailable.')
    with transaction.atomic():
        lock_accounts([actor.pk, target_id])
        current_actor = User.objects.select_for_update().filter(pk=actor.pk).first()
        target = User.objects.select_for_update().filter(pk=target_id).first()
        from .views import is_global_admin
        if (not current_actor or not active_admin(current_actor) or not target
                or target.pk == current_actor.pk or is_global_admin(target)):
            raise PermissionDenied('Account management is unavailable.')
        if ((expected_active is not None and target.is_active != expected_active)
                or (expected_version is not None and target.session_version != expected_version)):
            raise ValidationError('Account changed. Refresh before trying again.')
        if target.is_active == active:
            return False
        previous = target.is_active
        target.is_active = active
        # Reactivation also revokes legacy sessions whose older deactivation
        # predated session-version tracking. No-ops return before this point.
        target.session_version += 1
        models.QuerySet.update(User.objects.filter(pk=target.pk), is_active=target.is_active,
                               session_version=target.session_version)
        if not active:
            from .verification_delivery import cancel, Delivery
            cancel(Delivery.objects.filter(original_user_id=target.pk))
        record(current_actor, 'user.activation_changed', target,
               metadata={'previous_status': previous, 'new_status': active})
        return True
