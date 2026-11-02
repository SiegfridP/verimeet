from django.db import models
from django.core.exceptions import ValidationError
from accounts.models import Department, User

class Meeting(models.Model):
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
        if self.pk:
            self.full_clean()
        super().save(*args, **kwargs)

class Attendance(models.Model):
    meeting = models.ForeignKey(Meeting, on_delete=models.CASCADE, related_name='attendees')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    annotation = models.TextField(blank=True, null=True, help_text="Appended under the signature.")
    has_signed = models.BooleanField(default=False)
    cryptographic_signature = models.TextField(blank=True, null=True)
    signed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        unique_together = ('meeting', 'user')

class AuditLog(models.Model):
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    meeting = models.ForeignKey(Meeting, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=255) # e.g., "Changed status to Finished", "Signed Document"
    timestamp = models.DateTimeField(auto_now_add=True)
