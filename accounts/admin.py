from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Department, Membership
from django.db import transaction
from .audit import record
from django import forms
from django.db import models
from django.contrib.auth.forms import UserChangeForm
from .signatures import validate_signature_upload


class SignatureUserChangeForm(UserChangeForm):
    # A bounded FileField validates before saving; storage enforces the same
    # policy even when callers bypass forms or model full_clean().
    signature_image = forms.FileField(required=False, widget=forms.FileInput,
                                      validators=[validate_signature_upload])

    class Meta(UserChangeForm.Meta):
        model = User

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields.pop('signature_image', None)

@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'contact_email', 'is_active', 'created_at')
    search_fields = ('name',)

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            super().save_model(request, obj, form, change)
            if not change or form.changed_data:
                record(request.user, 'department.updated' if change else 'department.created',
                       obj, obj, {'changed_fields': sorted(form.changed_data)})

    def delete_model(self, request, obj):
        from .department_deletion import delete_with_audit
        delete_with_audit(request.user, obj)

    def has_delete_permission(self, request, obj=None):
        return (request.user.is_admin or request.user.is_superuser) and super().has_delete_permission(request, obj)

    def delete_queryset(self, request, queryset):
        from django.core.exceptions import PermissionDenied
        from django.db.models import F
        from .department_deletion import delete_with_audit
        if not (request.user.is_admin or request.user.is_superuser):
            raise PermissionDenied('Global Admin access required')
        using = queryset.db
        with transaction.atomic(using=using):
            departments = list(queryset.order_by('pk'))
            # Acquire all Department locks before any Meeting/Attendance locks.
            for department in departments:
                Department.objects.using(using).filter(pk=department.pk).update(name=F('name'))
            for department in departments:
                delete_with_audit(request.user, department, using=using)


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    readonly_fields = ('signature_status',)

    @admin.display(description='Signature status')
    def signature_status(self, obj):
        return 'Validated' if obj.signature_validated else 'Not validated'
    form = SignatureUserChangeForm
    # Generic file widgets must never ask private storage for a public URL.
    formfield_overrides = {models.ImageField: {'widget': forms.FileInput}}
    list_display = ('username', 'email', 'department', 'is_admin')
    list_filter = ('department', 'is_admin')
    fieldsets = UserAdmin.fieldsets + (
        ('VeriMeet SaaS Roles & Crypto', {
            'fields': ('department', 'is_admin', 'signature_status', 'public_key', 'private_key')
        }),
    )
    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            previous = User.objects.select_for_update().filter(pk=obj.pk).first() if change else None
            previous_memberships = set(Membership.objects.filter(user_id=obj.pk).values_list('pk', flat=True)) if change else set()
            super().save_model(request, obj, form, change)
            if previous:
                old_global = previous.is_admin or previous.is_superuser
                new_global = obj.is_admin or obj.is_superuser
                if old_global != new_global:
                    record(request.user, 'user.role_changed', obj, metadata={
                        'previous_role': 'Global Admin' if old_global else None,
                        'new_role': 'Global Admin' if new_global else None})
                if previous.is_active != obj.is_active:
                    record(request.user, 'user.activation_changed', obj, metadata={
                        'previous_status': previous.is_active, 'new_status': obj.is_active})
            for membership in Membership.objects.filter(user=obj).exclude(pk__in=previous_memberships):
                record(request.user, 'membership.added', membership, membership.department,
                       {'user_id': obj.pk, 'new_role': membership.role})

    def delete_model(self, request, obj):
        with transaction.atomic():
            for membership in Membership.objects.filter(user=obj):
                record(request.user, 'membership.removed', membership, membership.department,
                       {'user_id': obj.pk, 'previous_role': membership.role})
            super().delete_model(request, obj)

    def delete_queryset(self, request, queryset):
        with transaction.atomic():
            for obj in queryset:
                self.delete_model(request, obj)
