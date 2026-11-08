"""Department cascade safety for ORM, admin and application deletion."""
from django.core.exceptions import PermissionDenied
from django.db import router, transaction
from django.db.models import F, Q
from django.db.models.signals import pre_delete
from django.dispatch import receiver
from .models import Department, Membership
from .audit import record
from meetings.models import Meeting, Attendance, VerificationQR


@receiver(pre_delete, sender=Department, dispatch_uid='protect_department_evidence')
def protect_department_evidence(sender, instance, using, **kwargs):
    Department.objects.using(using).filter(pk=instance.pk).update(name=F('name'))
    meetings = Meeting.objects.using(using).filter(department_id=instance.pk)
    ids = list(meetings.order_by('pk').values_list('pk', flat=True))
    # Meeting before Attendance, matching existing signing/deletion guards.
    for pk in ids:
        Meeting.objects.using(using).filter(pk=pk).update(status=F('status'))
    attendance = Attendance.objects.using(using).filter(meeting_id__in=ids)
    list(attendance.select_for_update().order_by('pk'))
    if (meetings.filter(status__in=('Finished', 'Archived')).exists()
            or attendance.filter(Q(has_signed=True) | Q(signed_at__isnull=False)
                                 | (~Q(cryptographic_signature='') & Q(cryptographic_signature__isnull=False))).exists()
            or VerificationQR.objects.using(using).filter(attendance__meeting_id__in=ids).exists()):
        raise PermissionDenied('Department contains protected meeting or signature evidence and cannot be deleted.')


def delete_with_audit(actor, department, *, using=None):
    if not (actor.is_admin or actor.is_superuser):
        raise PermissionDenied('Global Admin access required')
    using = using or department._state.db or router.db_for_write(Department, instance=department)
    with transaction.atomic(using=using):
        # Lock the parent before the Collector can invoke Attendance receivers.
        # No-op UPDATE also obtains a write lock on SQLite.
        if not Department.objects.using(using).filter(pk=department.pk).update(name=F('name')):
            return
        for membership in Membership.objects.using(using).filter(department_id=department.pk).order_by('pk'):
            record(actor, 'membership.removed', membership, department,
                   {'user_id': membership.user_id, 'previous_role': membership.role}, using=using)
        record(actor, 'department.deleted', department, department, using=using)
        department.delete(using=using)
