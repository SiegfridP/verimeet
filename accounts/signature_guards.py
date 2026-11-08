"""Supported ORM upload guards. Raw SQL/private ORM internals remain trusted code."""
from django.core.exceptions import PermissionDenied
from django.db import models, transaction
from django.db.models import F
from django.contrib.auth.models import UserManager
from django.db.models.fields.files import ImageFieldFile


class SignatureFile(ImageFieldFile):
    def _initial_only(self):
        if self.instance.pk and type(self.instance).objects.filter(pk=self.instance.pk).exclude(
                signature_image='').exclude(signature_image__isnull=True).exists():
            raise PermissionDenied('Use the owner signature replacement service.')

    def save(self, name, content, save=True):
        with transaction.atomic():
            if self.instance.pk:
                users = type(self.instance).objects.filter(pk=self.instance.pk)
                if save:
                    from meetings.roster import lock_profile_names
                    lock_profile_names(users, users.db)
                users.update(username=F('username'))
            self._initial_only()
            return super().save(name, content, save)

    def delete(self, save=True):
        raise PermissionDenied('Signature deletion is disabled.')


class SignatureField(models.ImageField):
    attr_class = SignatureFile


class UserQuerySet(models.QuerySet):
    def update(self, **kwargs):
        if {'first_name', 'last_name', 'department', 'department_id'} & kwargs.keys():
            from meetings.roster import lock_profile_names
            with transaction.atomic(using=self.db):
                target = kwargs.get('department_id', kwargs.get('department'))
                if target is not None and not isinstance(target, int) and not hasattr(target, 'pk'):
                    raise PermissionDenied('Legacy department expression updates are unsupported.')
                extra = [getattr(target, 'pk', target)] if target is not None else []
                frozen = lock_profile_names(self, self.db, extra)
                return frozen._guarded_update(**kwargs)
        return self._guarded_update(**kwargs)

    def _guarded_update(self, **kwargs):
        if set(kwargs) & {'is_active', 'session_version'}:
            raise PermissionDenied('Use the account status service for session revocation.')
        if 'signature_image' in kwargs:
            value = kwargs['signature_image']
            if not isinstance(value, str) or self.exclude(signature_image=value).exists():
                raise PermissionDenied('Untracked signature replacement is disabled.')
            # Filename assignment is not an upload API. Even a no-op must stay
            # conditional so a concurrent change cannot be reverted.
            return super(UserQuerySet, self.filter(signature_image=value)).update(**kwargs)
        return super().update(**kwargs)

    def bulk_update(self, objs, fields, batch_size=None):
        if set(fields) & {'signature_image', 'session_version', 'is_active', 'first_name', 'last_name', 'department', 'department_id'}:
            raise PermissionDenied('Bulk updates to signature, names, account activity, or session-version fields are disabled.')
        return super().bulk_update(objs, fields, batch_size=batch_size)

    def bulk_create(self, objs, batch_size=None, ignore_conflicts=False, update_conflicts=False,
                    update_fields=None, unique_fields=None):
        if set(update_fields or []) & {'signature_image', 'session_version', 'is_active', 'first_name', 'last_name', 'department', 'department_id'}:
            raise PermissionDenied('Bulk conflict updates to signature, names, account activity, or session-version fields are disabled.')
        return super().bulk_create(objs, batch_size=batch_size, ignore_conflicts=ignore_conflicts,
            update_conflicts=update_conflicts, update_fields=update_fields, unique_fields=unique_fields)


class SignatureUserManager(UserManager.from_queryset(UserQuerySet)):
    pass
