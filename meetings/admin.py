from django.contrib import admin
from .models import Meeting, Attendance, AuditLog

class MeetingAdmin(admin.ModelAdmin):
    list_display = ('title', 'department', 'status', 'created_at', 'updated_at')
    list_filter = ('status', 'department')
    search_fields = ('title', 'minutes_content')

    def get_readonly_fields(self, request, obj=None):
        if obj and obj.status in ('Finished', 'Archived'):
            return ['title', 'minutes_content', 'department', 'status', 'created_at', 'updated_at']
        return ['status', 'created_at', 'updated_at']

admin.site.register(Meeting, MeetingAdmin)
admin.site.register(Attendance)
admin.site.register(AuditLog)
