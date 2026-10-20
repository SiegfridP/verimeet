from django.contrib import admin
from .models import Meeting, Attendance, AuditLog

admin.site.register(Meeting)
admin.site.register(Attendance)
admin.site.register(AuditLog)