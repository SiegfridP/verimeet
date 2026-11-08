"""Bounded PNG validation and private storage; never touches signing credentials."""
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import warnings
from PIL import Image
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.storage import FileSystemStorage
from django.core.files.base import ContentFile, File
from django.utils.deconstruct import deconstructible

LIMIT = 2097152


@deconstructible
class SignatureStorage(FileSystemStorage):
    def delete(self, name):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied('Physical signature deletion is disabled.')

    def save(self, name, content, max_length=None):
        # Common boundary for onboarding, Admin and FieldFile/model uploads.
        # Never reuse a caller-controlled path, including a legacy file's name.
        from uuid import uuid4
        data = normalize(File(content, name=name))
        return super().save('normalized/' + uuid4().hex + '.png',
                            ContentFile(data), max_length=max_length)

    @property
    def base_location(self):
        return settings.PRIVATE_SIGNATURE_ROOT

    @property
    def location(self):
        return str(Path(self.base_location).resolve())

    def url(self, name):
        raise NotImplementedError('Private signatures require an owner-authorized preview.')

    def path(self, name):
        if name.startswith('signatures/'):
            return FileSystemStorage(location=settings.MEDIA_ROOT).path(name)
        return super().path(name)


def decode_png(data):
    try:
        if not data or len(data) > LIMIT:
            raise ValueError()
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(BytesIO(data)) as image:
                if image.format != 'PNG' or not (0 < image.width <= 4096 and 0 < image.height <= 4096):
                    raise ValueError()
                if getattr(image, 'n_frames', 1) != 1:
                    raise ValueError()
                image.verify()
            with Image.open(BytesIO(data)) as image:
                image.load()
                return image.convert('RGBA')
    except Exception:
        raise ValidationError('Upload a valid, single-frame PNG up to 2 MiB and 4096 x 4096 pixels.') from None


def validate_signature_upload(upload):
    if not upload.name or Path(upload.name).suffix.lower() != '.png' or upload.size > LIMIT:
        raise ValidationError('Choose a .png file no larger than 2 MiB.')
    try:
        upload.seek(0)
        image = decode_png(upload.read(LIMIT + 1))
    finally:
        upload.seek(0)
    if not image.getchannel('A').getbbox():
        raise ValidationError('The PNG must contain a visible signature.')
    return image


def normalize(upload):
    image = validate_signature_upload(upload)
    transparent = image.getchannel('A').getextrema()[0] < 255
    if transparent:
        bounds = image.getchannel('A').getbbox()
        if not bounds:
            raise ValidationError('The PNG must contain a visible signature.')
        image = image.crop(bounds)
    image.thumbnail((580, 180), Image.Resampling.LANCZOS)
    canvas = Image.new('RGBA', (600, 200), (0, 0, 0, 0) if transparent else (255, 255, 255, 255))
    canvas.alpha_composite(image, ((600-image.width)//2, (200-image.height)//2))
    output = BytesIO()
    canvas.save(output, format='PNG')
    return output.getvalue()


def validated_signature_data(user):
    """Return a validated snapshot, or None. Hash every read to detect external edits.

    Only changed contents require decoding or a database write. Compare-and-swap
    prevents a stale User instance overwriting another validator's newer result.
    """
    field = user.signature_image
    if not field:
        return None
    try:
        with field.storage.open(field.name, 'rb') as stream:
            data = stream.read(LIMIT + 1)
        digest = sha256(field.name.encode() + b'\0' + data).hexdigest()
    except Exception:
        # Storage adapters may raise backend-specific exceptions. Fail closed.
        return None
    if digest != user.signature_validation_hash:
        try:
            if Path(field.name).suffix.lower() != '.png':
                raise ValidationError('PNG required')
            decode_png(data)
            valid = True
        except ValidationError:
            valid = False
        changed = get_user_model().objects.filter(
            pk=user.pk, signature_image=field.name,
            signature_validation_hash=user.signature_validation_hash,
            signature_validated=user.signature_validated,
        ).update(
            signature_validation_hash=digest, signature_validated=valid)
        if not changed:
            # A concurrent validation/upload won. Retry from fresh state next request.
            return None
        user.signature_validation_hash, user.signature_validated = digest, valid
        return data if valid else None
    # A matching in-memory hash is insufficient: another request may have
    # revoked validation or replaced the file reference since this User loaded.
    current = get_user_model().objects.filter(
        pk=user.pk, signature_image=field.name,
        signature_validation_hash=digest, signature_validated=True,
    ).exists()
    return data if user.signature_validated and current else None


def signature_valid(user):
    return validated_signature_data(user) is not None


def complete(user):
    from .views import is_global_admin
    return is_global_admin(user) or (bool(user.username) and not user.username_confirmation_required and signature_valid(user))
