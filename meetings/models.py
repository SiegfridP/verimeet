from django.db import models, router, transaction
from django.core.exceptions import ValidationError
from accounts.models import Department, User
from .evidence_objects import PrivateEvidenceObject  # Register private storage model.

class MeetingQuerySet(models.QuerySet):
    def update(self, **kwargs):
        from django.db.models import F
        value = kwargs.get('status')
        if 'status' in kwargs and not (isinstance(value, F) and value.name == 'status') and (not isinstance(value, str) or self.exclude(status=value).exists()):
            raise ValidationError('Finalize through Meeting.save(), not queryset update.')
        return super().update(**kwargs)

    def bulk_create(self, objs, **kwargs):
        objs = list(objs)
        if any(obj.status != 'Draft' for obj in objs):
            raise ValidationError('Bulk creation supports Draft meetings only.')
        return super().bulk_create(objs, **kwargs)


class Meeting(models.Model):
    objects = MeetingQuerySet.as_manager()
    STATUS_CHOICES = [
        ('Draft', 'Draft (Editable)'),
        ('Finished', 'Finished (Locked for Signing)'),
        ('Archived', 'Archived (PDF Generated)'),
    ]

    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    minutes_content = models.TextField(blank=True, help_text="The actual HTML/Text of the minutes.")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Draft')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} ({self.department.name})"

    def clean(self):
        super().clean()
        if not self.pk:
            return

        orig = Meeting.objects.filter(pk=self.pk).values(
            'status', 'title', 'minutes_content', 'department_id'
        ).first()
        if not orig:
            return

        # Content immutability for finalized or archived meetings
        if orig['status'] in ('Finished', 'Archived'):
            if (
                self.title != orig['title']
                or self.minutes_content != orig['minutes_content']
                or self.department_id != orig['department_id']
            ):
                raise ValidationError("Document content is immutable once finalized or archived.")

        # Irreversible status transition rules
        orig_status = orig['status']
        new_status = self.status
        if orig_status == 'Draft':
            if new_status not in ('Draft', 'Finished'):
                raise ValidationError("Invalid status transition from Draft.")
        elif orig_status == 'Finished':
            if new_status not in ('Finished', 'Archived'):
                raise ValidationError("Invalid status transition from Finished.")
        elif orig_status == 'Archived':
            if new_status != 'Archived':
                raise ValidationError("Archived meetings cannot change status.")

    def save(self, *args, **kwargs):
        using = kwargs.get('using') or router.db_for_write(type(self), instance=self)
        with transaction.atomic(using=using):
            from .roster import lock_departments, capture_roster
            initial = type(self).objects.using(using).filter(pk=self.pk).values('status', 'department_id').first() if self.pk else None
            finalizing = self.status in ('Finished', 'Archived') and (initial is None or initial['status'] == 'Draft')
            guarded_departments = {self.department_id} | ({initial['department_id']} if initial else set())
            if finalizing:
                lock_departments(guarded_departments, using)
            previous = None
            if self.pk:
                previous = type(self).objects.using(using).select_for_update().filter(
                    pk=self.pk
                ).values('status', 'department_id').first()
                if finalizing and previous and previous['department_id'] not in guarded_departments:
                    raise ValidationError('Meeting department changed. Retry finalization.')
                self.full_clean()
            super().save(*args, **kwargs)
            update_fields = kwargs.get('update_fields')
            writes_status = update_fields is None or 'status' in update_fields
            if writes_status and self.status in ('Finished', 'Archived') and (previous is None or previous['status'] == 'Draft'):
                capture_roster(self, using)
            if (previous and previous['status'] == 'Finished'
                    and self.status == 'Archived' and writes_status):
                AuditLog.objects.using(using).create(
                    department_id=self.department_id,
                    meeting=self,
                    user=None,
                    action='Archived document',
                    event_type='meeting.archived',
                    metadata={
                        'source': 'system',
                        'reason': 'No request actor available',
                        'meeting_id': self.pk,
                        'department_id': self.department_id,
                    },
                )

class AttendanceQuerySet(models.QuerySet):
    def update(self, **kwargs):
        if {'meeting','meeting_id','user','user_id'} & kwargs.keys():
            raise ValidationError('Structural assignment updates require Attendance.save().')
        return super().update(**kwargs)

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Use Attendance.save() for assignment creation.')


class Attendance(models.Model):
    objects = AttendanceQuerySet.as_manager()
    ATTENDANCE_STATUS_CHOICES = [
        ('Attended', 'Attended'),
        ('Late', 'Late'),
        ('Absent', 'Absent'),
    ]

    meeting = models.ForeignKey(Meeting, on_delete=models.CASCADE, related_name='attendees')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(
        max_length=20,
        choices=ATTENDANCE_STATUS_CHOICES,
        default='Absent'
    )
    status_updated_at = models.DateTimeField(null=True, blank=True)
    annotation = models.TextField(blank=True, null=True, help_text="Appended under the signature.")
    has_signed = models.BooleanField(default=False)
    cryptographic_signature = models.TextField(blank=True, null=True)
    signed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        unique_together = ('meeting', 'user')

    def save(self, *args, **kwargs):
        using = kwargs.get('using') or self._state.db or 'default'
        with transaction.atomic(using=using):
            from .roster import guard_assignment
            guard_assignment(self, using)
            return super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} - {self.meeting.title} ({self.status})"

    @property
    def verification_qr(self):
        return self.verification_qrs.filter(is_revoked=False).first()

class ImmutableSnapshotQuerySet(models.QuerySet):
    def update(self, **kwargs):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied('Signing snapshots are immutable.')

    def bulk_update(self, *args, **kwargs):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied('Signing snapshots are immutable.')

    def bulk_create(self, *args, **kwargs):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied('Use the signing evidence service.')


class SigningVisualSnapshot(models.Model):
    attendance = models.OneToOneField(Attendance, on_delete=models.PROTECT, related_name='visual_snapshot')
    storage_identifier = models.CharField(max_length=36, unique=True, editable=False)
    content_sha256 = models.CharField(max_length=64, editable=False)
    byte_length = models.PositiveIntegerField(editable=False)
    width = models.PositiveIntegerField(editable=False)
    height = models.PositiveIntegerField(editable=False)
    captured_at = models.DateTimeField(auto_now_add=True)
    signer_name = models.CharField(max_length=300, editable=False)
    provenance = models.CharField(max_length=32, default='signing-current-png', editable=False)
    objects = ImmutableSnapshotQuerySet.as_manager()

    def save(self, *args, **kwargs):
        from django.core.exceptions import PermissionDenied
        if not self._state.adding or (self.pk and type(self).objects.filter(pk=self.pk).exists()):
            raise PermissionDenied('Signing snapshots are immutable.')
        # Never let Django's insert fallback update a concurrently inserted PK.
        kwargs['force_insert'] = True
        return super().save(*args, **kwargs)


class AuditLog(models.Model):
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    meeting = models.ForeignKey(Meeting, on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=255) # e.g., "Changed status to Finished", "Signed Document"
    timestamp = models.DateTimeField(auto_now_add=True)
    event_type = models.CharField(max_length=64, default='legacy')
    metadata = models.JSONField(default=dict)
    target_type = models.CharField(max_length=64, blank=True)
    target_id = models.CharField(max_length=64, blank=True)

    @property
    def safe_metadata(self):
        allowed = {
            'format', 'export_scope', 'template_version', 'lifecycle_status', 'attendee_count',
            'source', 'reason', 'meeting_id', 'department_id', 'actor_id',
            'changed_fields', 'added_ids', 'removed_ids', 'added_count', 'removed_count',
            'participant_count', 'attendance_id', 'officer_id', 'previous_status',
            'new_status', 'method', 'signed_at', 'annotation_included', 'qr_session_id',
            'purpose', 'expires_at', 'verification_qr_id', 'previous_qr_id',
            'replacement_qr_id', 'previous_role', 'new_role', 'user_id',
            'previous_meeting_id', 'new_meeting_id', 'previous_officer_id',
            'new_officer_id', 'previous_department_id', 'new_department_id',
        }
        return {key: value for key, value in self.metadata.items() if key in allowed}

    def save(self, *args, **kwargs):
        if self._state.adding and self.event_type != 'legacy':
            # Retain stable identifiers without copying document or personal content.
            self.metadata = dict(self.metadata)
            for key, value in (('meeting_id', self.meeting_id),
                               ('department_id', self.department_id), ('actor_id', self.user_id)):
                if value is not None:
                    self.metadata.setdefault(key, value)
        super().save(*args, **kwargs)


class QRSession(models.Model):
    PURPOSE_ATTENDANCE = 'attendance'
    PURPOSE_SIGNING = 'signing'
    PURPOSE_CHOICES = [
        (PURPOSE_ATTENDANCE, 'Attendance'),
        (PURPOSE_SIGNING, 'Signing'),
    ]

    meeting = models.ForeignKey(Meeting, on_delete=models.CASCADE, related_name='qr_sessions')
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES)
    token = models.CharField(max_length=128, unique=True, db_index=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_qr_sessions')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='revoked_qr_sessions'
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        status = 'Revoked' if self.is_revoked else ('Expired' if self.is_expired else 'Active')
        return f"{self.meeting.title} - {self.get_purpose_display()} QR ({status})"

    @property
    def is_expired(self):
        from django.utils import timezone
        return timezone.now() > self.expires_at

    @property
    def is_active(self):
        return (not self.is_revoked) and (not self.is_expired)


class QRUsage(models.Model):
    qr_session = models.ForeignKey(QRSession, on_delete=models.CASCADE, related_name='usages')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='qr_usages')
    used_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('qr_session', 'user')

    def __str__(self):
        return f"{self.user.username} - {self.qr_session.purpose} on {self.qr_session.meeting.title}"


class VerificationQR(models.Model):
    """Batch 08: Individual signature verification QR code for a signed Attendance record.

    Completely separate from Batch 07 attendance/signing QRSession/QRUsage.
    Each QR belongs to exactly one Attendance record.
    The signer is the owner; the token proves their personal signed presence.
    """
    attendance = models.ForeignKey(
        Attendance,
        on_delete=models.CASCADE,
        related_name='verification_qrs',
    )
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    encrypted_token = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='revoked_verification_qrs'
    )

    class Meta:
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(
                fields=['attendance'],
                condition=models.Q(is_revoked=False),
                name='unique_active_verification_qr_per_attendance'
            )
        ]

    def __str__(self):
        status = 'Revoked' if self.is_revoked else 'Active'
        return f"{self.attendance.meeting.title} — {self.attendance.user.username} Signature Verification QR ({status})"

    @property
    def is_active(self):
        return not self.is_revoked

    @property
    def meeting(self):
        return self.attendance.meeting

    @property
    def signer(self):
        return self.attendance.user


class HistoricalRoster(models.Model):
    meeting = models.OneToOneField(Meeting, on_delete=models.PROTECT, related_name='historical_roster')
    captured_at = models.DateTimeField(auto_now_add=True)
    version = models.PositiveSmallIntegerField(default=1, editable=False)
    entries = models.JSONField(default=list, editable=False)
    objects = ImmutableSnapshotQuerySet.as_manager()

    def clean(self):
        from .roster import validate_entries
        validate_entries(self.entries)
        if self.version != 1:
            raise ValidationError('Unsupported roster version.')

    def save(self, *args, **kwargs):
        from django.core.exceptions import PermissionDenied
        if not self._state.adding or not getattr(self, '_capture_authorized', False):
            raise PermissionDenied('Historical rosters are immutable; use finalization.')
        self.full_clean()
        kwargs['force_insert'] = True
        return super().save(*args, **kwargs)
