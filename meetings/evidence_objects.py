"""Insert-only private evidence; raw SQL/database administrators remain trusted."""
from django.core.exceptions import PermissionDenied
from django.db import models


class EvidenceQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise PermissionDenied('Private evidence is immutable.')

    def delete(self):
        raise PermissionDenied('Private evidence must be retained.')

    def bulk_update(self, *args, **kwargs):
        raise PermissionDenied('Private evidence is immutable.')

    def bulk_create(self, *args, **kwargs):
        raise PermissionDenied('Create evidence through private storage.')


class PrivateEvidenceObject(models.Model):
    key = models.CharField(primary_key=True, max_length=255)
    data = models.BinaryField(editable=False)
    content_sha256 = models.CharField(max_length=64, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = EvidenceQuerySet.as_manager()

    class Meta:
        app_label = 'meetings'

    def save(self, *args, **kwargs):
        from hashlib import sha256
        if not self._state.adding:
            raise PermissionDenied('Private evidence is immutable.')
        if not 0 < len(self.data) <= 2097152 or sha256(bytes(self.data)).hexdigest() != self.content_sha256:
            raise ValueError('Invalid private evidence bytes.')
        kwargs['force_insert'] = True
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionDenied('Private evidence must be retained.')
