"""Write guards for attendance operations; callers must hold an atomic transaction."""
from django.core.exceptions import PermissionDenied
from django.db.models import F
from .models import Meeting


def lock_mutable_meetings(meeting_ids):
    # A conditional no-op UPDATE obtains a database write lock on SQLite too.
    # No lifecycle transition, timestamp change, or model-save event is produced.
    for meeting_id in sorted(set(meeting_ids)):
        if not Meeting.objects.filter(pk=meeting_id).exclude(status='Archived').update(status=F('status')):
            raise PermissionDenied('Archived meeting attendance is read-only.')
