"""Explicit, isolated initial signature uploads for regression request actors."""
from tempfile import TemporaryDirectory

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings

from .test_onboarding import png


def signature_storage(test):
    directory = TemporaryDirectory()
    test.addCleanup(directory.cleanup)
    settings = override_settings(PRIVATE_SIGNATURE_ROOT=directory.name, PRIVATE_SNAPSHOT_ROOT=None)
    settings.enable()
    test.addCleanup(settings.disable)


def complete_onboarding(*users):
    for user in users:
        user.signature_image.save('signature.png', SimpleUploadedFile('signature.png', png()))


def finalize_meeting_fixture(meeting, status='Finished'):
    """Finish only after fixture assignments exist; keep action audits out of setup."""
    from meetings.models import AuditLog
    meeting.status = 'Finished'
    meeting.save()
    if status == 'Archived':
        before = set(AuditLog.objects.values_list('pk', flat=True))
        meeting.status = 'Archived'
        meeting.save()
        AuditLog.objects.exclude(pk__in=before).filter(meeting=meeting, event_type='meeting.archived').delete()


def set_meeting_fixture_state(queryset, **fields):
    """Prepare supported lifecycle states without bypassing model integrity."""
    from meetings.models import AuditLog
    for meeting in queryset:
        target = fields.get('status', meeting.status)
        if target == 'Archived' and meeting.status == 'Draft':
            meeting.status = 'Finished'
            meeting.save()
        before = set(AuditLog.objects.values_list('pk', flat=True))
        for field, value in fields.items():
            setattr(meeting, field, value)
        meeting.save()
        AuditLog.objects.exclude(pk__in=before).filter(meeting=meeting, event_type='meeting.archived').delete()
