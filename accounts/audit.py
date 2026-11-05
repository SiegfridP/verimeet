"""Safe administrative event helpers. Call inside the mutation transaction."""
from meetings.models import AuditLog
from .models import Membership


def record(actor, event_type, target, department=None, metadata=None):
    return AuditLog.objects.create(
        user=actor if actor and actor.is_authenticated else None,
        department=department, event_type=event_type, action=event_type,
        target_type=target._meta.model_name, target_id=str(target.pk),
        metadata=metadata or {},
    )


def grant_ap(actor, user, department):
    membership, created = Membership.objects.select_for_update().get_or_create(
        user=user, department=department, defaults={'role': 'AP'}
    )
    previous = membership.role
    if created:
        record(actor, 'membership.added', membership, department,
               {'user_id': user.pk, 'new_role': 'AP'})
    elif previous != 'AP':
        membership.role = 'AP'
        membership.save(update_fields=['role'])
        record(actor, 'user.role_changed', membership, department,
               {'user_id': user.pk, 'previous_role': previous, 'new_role': 'AP'})
    return membership
