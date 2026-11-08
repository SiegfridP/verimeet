"""Preserve protected attendance even when Django collects it through a parent."""
from django.core.exceptions import PermissionDenied
from django.db.models import F
from django.db.models.signals import pre_delete
from django.dispatch import receiver
from .models import Attendance, Meeting, SigningVisualSnapshot


@receiver(pre_delete, sender=SigningVisualSnapshot)
def protect_snapshot(sender, instance, **kwargs):
    raise PermissionDenied('Signing snapshots must be retained.')


@receiver(pre_delete, sender=Attendance, dispatch_uid='protect_attendance_evidence')
def protect_attendance_evidence(sender, instance, using, **kwargs):
    # Collector sends pre_delete inside its atomic block, before deleting any row.
    # A listener also disables fast deletion for Attendance. Use persisted state:
    # cascade instances may have been collected before a concurrent signing write.
    meeting_id = Attendance.objects.using(using).filter(pk=instance.pk).values_list('meeting_id', flat=True).first()
    if meeting_id is None:
        return
    # Acquire a write lock on SQLite as well; do not call save(), change timestamps,
    # or create lifecycle/audit events. Other supported integrity writes use this row.
    Meeting.objects.using(using).filter(pk=meeting_id).update(status=F('status'))
    persisted = Attendance.objects.using(using).select_for_update().filter(pk=instance.pk).first()
    if persisted is None:
        return
    if persisted.meeting_id != meeting_id:
        # Do not lock a different Meeting while holding Attendance: fail closed
        # if reassignment won the race between discovery and lock acquisition.
        raise PermissionDenied('Attendance changed during deletion. Nothing was deleted; please retry.')
    meeting_status = Meeting.objects.using(using).values_list('status', flat=True).get(pk=meeting_id)
    if (persisted.has_signed or persisted.cryptographic_signature or persisted.signed_at
            or meeting_status in ('Finished', 'Archived')
            or SigningVisualSnapshot.objects.using(using).filter(attendance_id=persisted.pk).exists()):
        raise PermissionDenied(
            'Deletion rejected: signed or finalized attendance and its verification history must be retained. '
            'The parent record cannot be deleted.'
        )


from .models import HistoricalRoster

@receiver(pre_delete, sender=HistoricalRoster)
def protect_historical_roster(sender, instance, **kwargs):
    raise PermissionDenied('Historical rosters must be retained.')


from accounts.models import Membership
@receiver(pre_delete, sender=Membership)
def serialize_membership_removal(sender, instance, using, **kwargs):
    from .roster import lock_user_scope
    lock_user_scope([instance.user_id], using, [instance.department_id])
