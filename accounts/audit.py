"""Safe administrative event helpers. Call inside the mutation transaction."""
from meetings.models import AuditLog
from .models import Membership
from django.core.exceptions import ValidationError
from django.db.models import F
from .models import Department


def record(actor, event_type, target, department=None, metadata=None, *, using=None):
    return AuditLog.objects.db_manager(using).create(
        user=actor if actor and actor.is_authenticated else None,
        department=department, event_type=event_type, action=event_type,
        target_type=target._meta.model_name, target_id=str(target.pk),
        metadata=metadata or {},
    )


def grant_ap(actor, user, department):
    from meetings.roster import lock_user_scope
    lock_user_scope([user.pk], extra_departments=[department.pk])
    if not Department.objects.filter(pk=department.pk, is_active=True).update(name=F('name')):
        raise ValidationError('Active department membership required.')
    membership = Membership.objects.select_for_update().filter(user=user, department=department).first()
    if membership is None:
        raise ValidationError('Active department membership required.')
    previous = membership.role
    if previous != 'AP':
        membership.role = 'AP'
        membership.save(update_fields=['role'])
        record(actor, 'user.role_changed', membership, department,
               {'user_id': user.pk, 'previous_role': previous, 'new_role': 'AP'})
    return membership
