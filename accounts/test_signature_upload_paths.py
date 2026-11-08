"""New uploads share one storage policy; existing files are never normalized on save."""
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.forms import modelform_factory
from django.test import TestCase, override_settings
from django.db import transaction
from PIL import Image
from .admin import SignatureUserChangeForm
from .models import User
from .signatures import LIMIT, normalize, signature_valid
from .test_onboarding import png


class SignatureUploadPathTests(TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.private = Path(self.directory.name) / 'private'
        self.media = Path(self.directory.name) / 'media'
        override = override_settings(PRIVATE_SIGNATURE_ROOT=self.private, MEDIA_ROOT=self.media)
        override.enable()
        self.addCleanup(override.disable)
        self.user = User.objects.create_user(username='upload-paths')
        self.admin_form = modelform_factory(User, form=SignatureUserChangeForm,
                                           fields=['username', 'signature_image'])

    def upload(self, path, data, name='signature.png'):
        upload = SimpleUploadedFile(name, data)
        if path == 'admin':
            form = self.admin_form({'username': self.user.username}, {'signature_image': upload}, instance=self.user)
            if not form.is_valid():
                raise ValidationError(form.errors.as_text())
            form.save()
        elif path == 'assignment':
            self.user.signature_image = upload
            self.user.save()  # Model save does not call full_clean().
        elif path == 'fieldfile':
            self.user.signature_image.save(name, upload)
        else:
            return self.user.signature_image.storage.save(name, upload)
        self.user.refresh_from_db()
        return self.user.signature_image.name

    def test_all_new_upload_paths_normalize_privately_without_double_formatting(self):
        from PIL.PngImagePlugin import PngInfo
        opaque = png((3000, 1000), mode='RGB', color='navy')
        image = Image.new('RGBA', (100, 100), (0, 0, 0, 0))
        image.paste((0, 0, 0, 255), (40, 45, 60, 55))
        stream = BytesIO(); metadata = PngInfo(); metadata.add_text('private', 'remove')
        image.save(stream, 'PNG', pnginfo=metadata)
        for path in ('admin', 'assignment', 'fieldfile', 'storage'):
            for data in (opaque, stream.getvalue(), png()):
                with self.subTest(path=path, input_size=len(data)):
                    name = self.upload(path, data)
                    self.assertRegex(name, r'^normalized/[0-9a-f]{32}\.png$')
                    saved = (self.private / name).read_bytes()
                    self.assertEqual(saved, normalize(SimpleUploadedFile('signature.png', data)))
                    result = Image.open(BytesIO(saved))
                    self.assertEqual(result.size, (600, 200))
                    self.assertNotIn('private', result.info)
                    self.assertFalse((self.media / name).exists())
        with self.assertRaises(NotImplementedError):
            self.user.signature_image.storage.url(name)

    def test_all_paths_reject_invalid_inputs_before_file_or_database_write(self):
        jpeg = BytesIO(); Image.new('RGB', (10, 10)).save(jpeg, 'JPEG')
        animated = BytesIO()
        Image.new('RGBA', (10, 10), 'black').save(animated, 'PNG', save_all=True,
            append_images=[Image.new('RGBA', (10, 10), 'white')], duration=10)
        invalid = [('signature.png', jpeg.getvalue()), ('signature.png', b'corrupt'),
                   ('signature.png', png()[:30]), ('signature.png', b'x' * (LIMIT + 1)),
                   ('signature.png', png((4097, 1))), ('signature.png', png((1, 4097))),
                   ('signature.png', animated.getvalue()), ('signature.jpg', png()),
                   ('signature.png', png(color=(0, 0, 0, 0)))]
        for path in ('admin', 'assignment', 'fieldfile', 'storage'):
            for name, data in invalid:
                with self.subTest(path=path, name=name, size=len(data)):
                    self.user.refresh_from_db()
                    with self.assertRaises(ValidationError):
                        with transaction.atomic():
                            self.upload(path, data, name)
                    self.user.refresh_from_db()
                    self.assertFalse(self.user.signature_image)
                    self.assertEqual(list(self.private.rglob('*.png')), [])

    def test_existing_legacy_signature_is_not_rewritten_by_model_or_admin(self):
        original = png((100, 50))
        name = FileSystemStorage(location=self.media).save('signatures/legacy.png', ContentFile(original))
        User.objects.filter(pk=self.user.pk).update(signature_image=name)
        self.user.refresh_from_db()
        keys = (self.user.public_key, self.user.private_key)
        self.assertTrue(signature_valid(self.user))
        self.user.save()
        form = self.admin_form({'username': self.user.username}, instance=self.user)
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.user.refresh_from_db()
        self.assertEqual(self.user.signature_image.name, name)
        self.assertEqual((self.media / name).read_bytes(), original)
        self.assertEqual(list(self.private.rglob('*.png')), [])
        self.assertEqual((self.user.public_key, self.user.private_key), keys)

    def test_new_upload_never_overwrites_caller_supplied_legacy_path(self):
        legacy = FileSystemStorage(location=self.media)
        name = legacy.save('signatures/keep.png', ContentFile(png((50, 20))))
        before = (self.media / name).read_bytes()
        storage = self.user.signature_image.storage
        first = storage.save(name, ContentFile(png()))
        second = storage.save(name, ContentFile(png()))
        self.assertNotEqual(first, second)
        self.assertEqual((self.media / name).read_bytes(), before)
        self.assertTrue((self.private / first).exists())
