from datetime import timedelta
from hashlib import sha256
from django.conf import settings
from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models, transaction
from django.db.models import F
from django.utils import timezone
from .models import User, RetainedSignature
from .signatures import complete, validated_signature_data
from .audit import record


def version(user):
    digest = sha256((user.signature_image.name + '\0' + user.signature_validation_hash).encode()).hexdigest()
    return signing.dumps([user.pk, digest], salt='signature-replacement')


def _recover_onboarding_signature(user, upload):
    """Internal recovery only: valid active assets can never use this path."""
    from .signatures import signature_valid
    days = getattr(settings, 'SIGNATURE_RETENTION_DAYS', 90)
    if not isinstance(days, int) or isinstance(days, bool) or days < 90:
        raise ValidationError('Retention must be at least 90 days.')
    expected = (user.signature_image.name, user.signature_validation_hash, user.signature_validated)
    with transaction.atomic():
        User.objects.filter(pk=user.pk).update(username=F('username'))
        current = User.objects.select_for_update().get(pk=user.pk)
        from .views import is_global_admin
        if not current.is_active or is_global_admin(current):
            raise PermissionDenied('Signature management is unavailable.')
        if expected != (current.signature_image.name, current.signature_validation_hash, current.signature_validated):
            raise ValidationError('Signature changed. Refresh onboarding.')
        if not current.signature_image or signature_valid(current):
            raise PermissionDenied('Valid signatures require explicit replacement.')
        old = current.signature_image.name
        digest, size = '', None
        try:
            with current.signature_image.open('rb') as stream:
                old_data = stream.read(2097153)
            if len(old_data) <= 2097152:
                digest, size = sha256(old_data).hexdigest(), len(old_data)
        except OSError:
            pass  # Missing/unreadable legacy assets retain an unresolved reference.
        new = current.signature_image.storage.save(upload.name, upload)
        with current.signature_image.storage.open(new, 'rb') as stream:
            data = stream.read(2097153)
        from .signatures import decode_png
        decode_png(data)
        now = timezone.now()
        RetainedSignature.objects.create(owner=current, owner_identifier=str(current.pk), actor_identifier=str(current.pk),
            storage_namespace='legacy' if old.startswith('signatures/') else 'private', storage_identifier=old,
            superseded_at=now, eligible_at=now+timedelta(days=days), state='unresolved', source='onboarding',
            content_sha256=digest, file_size=size)
        if models.QuerySet.update(User.objects.filter(pk=current.pk, signature_image=old,
                signature_validation_hash=current.signature_validation_hash, signature_validated=current.signature_validated),
                signature_image=new, signature_validation_hash=sha256(new.encode()+b'\0'+data).hexdigest(),
                signature_validated=True) != 1:
            raise ValidationError('Signature changed. Refresh onboarding.')
        record(current, 'user.signature_recovered', current)
        return new


def replace_signature(owner, upload, expected_version):
    from .views import is_global_admin
    if not owner.is_authenticated or is_global_admin(owner):
        raise PermissionDenied('Signature management is unavailable.')
    days = getattr(settings, 'SIGNATURE_RETENTION_DAYS', 90)
    if not isinstance(days, int) or isinstance(days, bool) or days < 90:
        raise ValidationError('Signature retention must be at least 90 days.')
    with transaction.atomic():
        # No-op write serializes SQLite too, before reading replacement state.
        User.objects.filter(pk=owner.pk).update(username=F('username'))
        user = User.objects.select_for_update().get(pk=owner.pk)
        if not user.is_active or is_global_admin(user) or not complete(user):
            raise PermissionDenied('Complete onboarding before replacing a signature.')
        try:
            supplied = signing.loads(expected_version, salt='signature-replacement', max_age=86400)
            current = signing.loads(version(user), salt='signature-replacement')
            if supplied != current:
                raise signing.BadSignature()
        except (signing.BadSignature, TypeError):
            raise ValidationError('Your signature changed. Refresh Settings before trying again.') from None
        old_data = validated_signature_data(user)
        if old_data is None:
            raise ValidationError('The current signature is unavailable. Refresh Settings.')
        old_name = user.signature_image.name
        # Filesystem writes cannot roll back. Failed new files stay private for reconciliation.
        new_name = user.signature_image.storage.save(upload.name, upload)
        with user.signature_image.storage.open(new_name, 'rb') as stream:
            new_data = stream.read(2097153)
        from .signatures import decode_png
        decode_png(new_data)
        now = timezone.now()
        retained = RetainedSignature.objects.create(owner=user, owner_identifier=str(user.pk),
            actor_identifier=str(user.pk), storage_namespace='legacy' if old_name.startswith('signatures/') else 'private',
            storage_identifier=old_name, superseded_at=now, eligible_at=now+timedelta(days=days),
            content_sha256=sha256(old_data).hexdigest(), file_size=len(old_data))
        # Deliberate private ORM boundary: no public flag disables model guards.
        changed = models.QuerySet.update(User.objects.filter(pk=user.pk, signature_image=old_name,
            signature_validation_hash=user.signature_validation_hash), signature_image=new_name,
            signature_validation_hash=sha256(new_name.encode()+b'\0'+new_data).hexdigest(), signature_validated=True)
        if changed != 1:
            raise ValidationError('Your signature changed. Refresh Settings.')
        record(user, 'user.signature_replaced', user)
        return retained.pk
