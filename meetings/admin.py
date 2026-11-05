from django.contrib import admin
from .models import Meeting, Attendance, AuditLog
from django.db import transaction

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
            previous = Attendance.objects.select_for_update().filter(pk=obj.pk).first() if change else None
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
            persisted = Attendance.objects.select_for_update().filter(pk=obj.pk).first()
            if persisted is not None:
                self._record(request, persisted, persisted, 'attendance.deleted', 'Deleted attendance assignment')
                super().delete_model(request, persisted)

    def delete_queryset(self, request, queryset):
        with transaction.atomic():
            for obj in queryset:
                self.delete_model(request, obj)


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
