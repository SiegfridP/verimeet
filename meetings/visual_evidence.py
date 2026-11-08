"""Private immutable signing assets. Storage writes cannot roll back with SQL."""
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from accounts.signatures import LIMIT, decode_png, validated_signature_data
from core.private_storage import DurablePrivateMixin


class SnapshotStorage(DurablePrivateMixin, FileSystemStorage):
    evidence_prefix = 'snapshots'
    def save(self, name, content, max_length=None):
        if len(name) != 36 or not name.endswith('.png'):
            raise ValueError('Invalid evidence identifier')
        int(name[:-4], 16)
        data = content.read(LIMIT + 1)
        decode_png(data)
        return super().save(name, ContentFile(data), max_length=max_length)

    @property
    def location(self):
        root = getattr(settings, 'PRIVATE_SNAPSHOT_ROOT', None)
        return str(Path(root or Path(settings.PRIVATE_SIGNATURE_ROOT) / 'signing-evidence').resolve())

    def url(self, name):
        raise PermissionDenied('Private evidence has no public URL.')

    def delete(self, name):
        raise PermissionDenied('Signing evidence must be retained.')


def read_snapshot(identifier, digest, size, width, height):
    try:
        if not identifier or len(identifier) != 36 or not identifier.endswith('.png'):
            return None
        int(identifier[:-4], 16)
        with SnapshotStorage().open(identifier, 'rb') as stream:
            data = stream.read(LIMIT + 1)
        if len(data) != size or sha256(data).hexdigest() != digest:
            return None
        image = decode_png(data)
        if image.size != (width, height):
            return None
        return data
    except Exception:
        return None


def capture(attendance, user):
    from .models import SigningVisualSnapshot
    data = validated_signature_data(user)
    if data is None:
        raise ValueError('Visual signature unavailable')
    image = decode_png(data)
    if not image.getchannel('A').getbbox():
        raise ValueError('Visual signature unavailable')
    name = uuid4().hex + '.png'
    stored = SnapshotStorage().save(name, ContentFile(data))
    digest = sha256(data).hexdigest()
    if stored != name or read_snapshot(stored, digest, len(data), *image.size) != data:
        raise ValueError('Evidence persistence failed')
    return SigningVisualSnapshot.objects.create(
        attendance=attendance, storage_identifier=stored, content_sha256=digest,
        byte_length=len(data), width=image.width, height=image.height,
        signer_name=user.get_full_name().strip()[:300] or 'Name unavailable')
