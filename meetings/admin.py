from django.contrib import admin
from .models import Meeting, Attendance, AuditLog
from django.db import transaction
from django.core.exceptions import PermissionDenied
from django import forms
from .attendance_integrity import lock_mutable_meetings


class AttendanceAdminForm(forms.ModelForm):
    class Meta:
        model = Attendance
        fields = '__all__'

    def clean(self):
        data = super().clean()
        previous = Attendance.objects.filter(pk=self.instance.pk).first()
        meetings = [data.get('meeting')]
        if previous:
            meetings.append(previous.meeting)
            if previous.has_signed or previous.cryptographic_signature or previous.signed_at:
                raise forms.ValidationError('Signed attendance is read-only in Admin.')
        if any(meeting and meeting.status == 'Archived' for meeting in meetings):
            raise forms.ValidationError('Archived meeting attendance is read-only.')
        return data

class MeetingAdmin(admin.ModelAdmin):
    list_display = ('title', 'department', 'status', 'created_at', 'updated_at')
    list_filter = ('status', 'department')
    search_fields = ('title', 'minutes_content')

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            previous = Meeting.objects.select_for_update().filter(pk=obj.pk).first() if change else None
            super().save_model(request, obj, form, change)
            changed = [name for name in ('title', 'minutes_content', 'department')
                       if previous and getattr(previous, name) != getattr(obj, name)]
            metadata = {'changed_fields': changed}
            if 'department' in changed:
                metadata.update(previous_department_id=previous.department_id,
                                new_department_id=obj.department_id)
            if not change or changed:
                AuditLog.objects.create(
                    user=request.user, meeting=obj, department=obj.department,
                    action='Edited draft meeting minutes' if change else 'Created meeting',
                    event_type='meeting.edited' if change else 'meeting.created',
                    target_type='meeting', target_id=str(obj.pk),
                    metadata=metadata,
                )

    def get_readonly_fields(self, request, obj=None):
        if obj and obj.status in ('Finished', 'Archived'):
            return ['title', 'minutes_content', 'department', 'status', 'created_at', 'updated_at']
        return ['status', 'created_at', 'updated_at']

admin.site.register(Meeting, MeetingAdmin)
@admin.register(Attendance)
class AttendanceAdmin(admin.ModelAdmin):
    form = AttendanceAdminForm

    def _protected(self, obj):
        return obj and (obj.has_signed or obj.cryptographic_signature or obj.signed_at
                        or obj.meeting.status == 'Archived')

    def get_readonly_fields(self, request, obj=None):
        if self._protected(obj):
            return [field.name for field in Attendance._meta.fields]
        # Signing material is produced only by the signing workflow.
        return ['has_signed', 'cryptographic_signature', 'signed_at', 'annotation']

    def has_delete_permission(self, request, obj=None):
        return not self._protected(obj) and super().has_delete_permission(request, obj)

    def _record(self, request, obj, previous, event_type, action):
        AuditLog.objects.create(
            user=request.user, meeting=obj.meeting, department=obj.meeting.department,
            action=action, event_type=event_type,
            target_type='attendance', target_id=str(obj.pk),
            metadata={
                'attendance_id': obj.pk, 'officer_id': obj.user_id,
                'previous_meeting_id': previous.meeting_id if previous else None,
                'new_meeting_id': obj.meeting_id if event_type != 'attendance.deleted' else None,
                'previous_officer_id': previous.user_id if previous else None,
                'new_officer_id': obj.user_id if event_type != 'attendance.deleted' else None,
                'previous_department_id': previous.meeting.department_id if previous else None,
                'new_department_id': obj.meeting.department_id if event_type != 'attendance.deleted' else None,
                'previous_status': previous.status if previous else None,
                'new_status': obj.status if event_type != 'attendance.deleted' else None,
                'method': 'manual',
            },
        )

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            original_meeting_id = (Attendance.objects.filter(pk=obj.pk).values_list('meeting_id', flat=True).first()
                                   if change else None)
            if change and original_meeting_id is None:
                raise PermissionDenied('Attendance no longer exists. Please reload.')
            lock_mutable_meetings([obj.meeting_id] + ([original_meeting_id] if change else []))
            previous = Attendance.objects.select_for_update().filter(pk=obj.pk).first() if change else None
            if change and (previous is None or previous.meeting_id != original_meeting_id):
                raise PermissionDenied('Attendance changed during this operation. Nothing was saved; please retry.')
            if self._protected(previous):
                raise PermissionDenied('Signed attendance is read-only in Admin.')
            if any(getattr(obj, field) != (getattr(previous, field) if previous else default)
                   for field, default in (('has_signed', False), ('cryptographic_signature', None),
                                          ('signed_at', None), ('annotation', None))):
                # Blank strings and NULL are equivalent for unsigned material.
                if any(getattr(obj, field) or (previous and getattr(previous, field))
                       for field in ('has_signed', 'cryptographic_signature', 'signed_at', 'annotation')):
                    raise PermissionDenied('Signature fields may only be set by the signing workflow.')
            super().save_model(request, obj, form, change)
            if previous is None:
                self._record(request, obj, None, 'attendance.created', 'Created attendance assignment')
            elif (previous.meeting_id, previous.user_id) != (obj.meeting_id, obj.user_id):
                self._record(request, obj, previous, 'attendance.reassigned', 'Reassigned attendance')
            elif previous.status != obj.status:
                self._record(request, obj, previous, 'attendance.changed',
                             f'Changed attendance for {obj.user.username} from {previous.status} to {obj.status}')

    def delete_model(self, request, obj):
        with transaction.atomic():
            original_meeting_id = Attendance.objects.filter(pk=obj.pk).values_list('meeting_id', flat=True).first()
            if original_meeting_id is None:
                return
            lock_mutable_meetings([original_meeting_id])
            persisted = Attendance.objects.select_for_update().filter(pk=obj.pk).first()
            if persisted is not None and persisted.meeting_id != original_meeting_id:
                raise PermissionDenied('Attendance changed during deletion. Nothing was deleted; please retry.')
            if persisted is not None:
                if self._protected(persisted):
                    raise PermissionDenied('Signed attendance cannot be deleted.')
                self._record(request, persisted, persisted, 'attendance.deleted', 'Deleted attendance assignment')
                super().delete_model(request, persisted)

    def delete_queryset(self, request, queryset):
        with transaction.atomic():
            associations = dict(queryset.values_list('pk', 'meeting_id'))
            lock_mutable_meetings(associations.values())
            objects = list(Attendance.objects.filter(pk__in=associations).order_by('pk').select_for_update())
            if len(objects) != len(associations) or any(obj.meeting_id != associations[obj.pk] for obj in objects):
                raise PermissionDenied('Attendance changed during deletion. Nothing was deleted; please retry.')
            if any(self._protected(obj) for obj in objects):
                raise PermissionDenied('Protected attendance cannot be deleted; nothing was deleted.')
            for obj in objects:
                self._record(request, obj, obj, 'attendance.deleted', 'Deleted attendance assignment')
                super().delete_model(request, obj)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'event_type', 'user', 'meeting', 'department')
    list_filter = ('event_type', 'department')
    actions = None

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        if request.user.is_superuser or request.user.is_admin:
            return queryset
        return queryset.filter(
            department__memberships__user=request.user,
            department__memberships__role='AP',
        ).distinct()

    def get_list_filter(self, request):
        if request.user.is_superuser or request.user.is_admin:
            return self.list_filter
        return ('event_type',)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
