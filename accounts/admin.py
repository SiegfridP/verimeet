from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Department

@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'contact_email', 'is_active', 'created_at')
    search_fields = ('name',)

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'department', 'is_admin')
    list_filter = ('department', 'is_admin')
    fieldsets = UserAdmin.fieldsets + (
        ('VeriMeet SaaS Roles & Crypto', {
            'fields': ('department', 'is_admin', 'signature_image', 'public_key', 'private_key')
        }),
    )