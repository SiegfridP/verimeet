from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Department, Membership
from django.db import transaction
from .audit import record
from django import forms
from django.db import models
from django.contrib.auth.forms import UserChangeForm
from .signatures import validate_signature_upload
from django.core import signing


SECURITY_FLAGS = ('is_admin', 'is_superuser', 'is_staff', 'is_active')


def valid_security_snapshot(pk, baseline, target_pk):
    return (type(pk) is int and pk == target_pk and type(baseline) is dict
            and set(baseline) == {*SECURITY_FLAGS, 'session_version'}
            and all(type(baseline[field]) is bool for field in SECURITY_FLAGS)
            and type(baseline['session_version']) is int and baseline['session_version'] >= 0)


class SignatureUserChangeForm(UserChangeForm):
    security_state = forms.CharField(required=False, widget=forms.HiddenInput)
    confirm_account_status = forms.BooleanField(required=False,
        label='I confirm this account status change and session revocation.')
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
            flags = (*SECURITY_FLAGS, 'session_version')
            self.security_initial = {field: getattr(self.instance, field) for field in flags}
            self.fields['security_state'].initial = signing.dumps(
                [self.instance.pk, self.security_initial], salt='admin-security-state')
            if self.is_bound:
                try:
                    snapshot = signing.loads(self.data.get('security_state', ''),
                                             salt='admin-security-state', max_age=3600)
                    if type(snapshot) is not list or len(snapshot) != 2:
                        raise signing.BadSignature()
                    pk, baseline = snapshot
                    if not valid_security_snapshot(pk, baseline, self.instance.pk):
                        raise signing.BadSignature()
                    self.security_initial = baseline
                    # Compare posted flags to what the administrator actually saw.
                    self.initial.update(baseline)
                except (signing.BadSignature, ValueError, TypeError):
                    self.security_initial = None

    def clean(self):
        data = super().clean()
        if self.instance.pk and getattr(self, 'security_initial', None) is None:
            self.add_error('security_state', 'Refresh this account before editing security state.')
        baseline = getattr(self, 'security_initial', None)
        if (self.instance.pk and baseline is not None and 'is_active' in self.fields
                and data.get('is_active') != baseline['is_active'] and not data.get('confirm_account_status')):
            self.add_error('confirm_account_status', 'Confirm the account status change.')
        return data

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
            'fields': ('department', 'is_admin', 'signature_status', 'confirm_account_status', 'security_state', 'public_key', 'private_key')
        }),
    )
    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            from .account_status import lock_accounts, change_account_status
            from django.core.exceptions import PermissionDenied
            if change and {'first_name', 'last_name', 'department'}.intersection(form.changed_data):
                from meetings.roster import lock_profile_names
                lock_profile_names(User.objects.filter(pk=obj.pk), extra_departments=[obj.department_id])
            if change and 'is_active' in form.changed_data:
                from meetings.roster import lock_user_scope
                lock_user_scope([request.user.pk, obj.pk])
            lock_accounts([request.user.pk] + ([obj.pk] if change else []))
            previous = User.objects.select_for_update().filter(pk=obj.pk).first() if change else None
            previous_memberships = set(Membership.objects.filter(user_id=obj.pk).values_list('pk', flat=True)) if change else set()
            if previous:
                baseline = getattr(form, 'security_initial', None)
                if (not valid_security_snapshot(obj.pk, baseline, previous.pk)
                        or previous.is_active != baseline['is_active']
                        or previous.session_version != baseline['session_version']):
                    raise PermissionDenied('Account security state changed. Refresh before editing.')
                for field in ('is_admin', 'is_superuser', 'is_staff'):
                    if field not in form.changed_data:
                        setattr(obj, field, getattr(previous, field))
                    else:
                        baseline = getattr(form, 'security_initial', None)
                        if baseline is None or baseline[field] != getattr(previous, field):
                            raise PermissionDenied('Privileges changed. Refresh before editing.')
                # Status editing must not restore a password hash from a stale form.
                if 'password' not in form.changed_data:
                    obj.password = previous.password
                if obj.is_active != baseline['is_active']:
                    if not form.cleaned_data.get('confirm_account_status'):
                        raise PermissionDenied('Explicit status confirmation required.')
                    if previous.is_admin or previous.is_superuser or obj.is_admin or obj.is_superuser:
                        raise PermissionDenied('Global Admin accounts are protected.')
                    change_account_status(request.user, obj.pk, obj.is_active,
                                          expected_active=baseline['is_active'], expected_version=baseline['session_version'])
                else:
                    obj.is_active = previous.is_active
                obj.session_version = User.objects.values_list('session_version', flat=True).get(pk=obj.pk)
            super().save_model(request, obj, form, change)
            if previous:
                old_global = previous.is_admin or previous.is_superuser
                new_global = obj.is_admin or obj.is_superuser
                if old_global != new_global:
                    record(request.user, 'user.role_changed', obj, metadata={
                        'previous_role': 'Global Admin' if old_global else None,
                        'new_role': 'Global Admin' if new_global else None})
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
