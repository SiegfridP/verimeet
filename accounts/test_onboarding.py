from io import BytesIO
from tempfile import TemporaryDirectory
from unittest.mock import patch
from PIL import Image
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from .models import User, Department, Membership
from .signatures import normalize, signature_valid


def png(size=(30, 10), mode='RGBA', color=(0, 0, 0, 255), **options):
    stream = BytesIO()
    Image.new(mode, size, color).save(stream, format='PNG', **options)
    return stream.getvalue()


class OnboardingTests(TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        setting = override_settings(PRIVATE_SIGNATURE_ROOT=self.directory.name)
        setting.enable()
        self.addCleanup(setting.disable)
        self.user = User.objects.create_user(username='participant')
        self.client.force_login(self.user)

    def upload(self, data=None, **extra):
        return self.client.post(reverse('onboarding'), {
            'signature': SimpleUploadedFile('signature.png', data if data is not None else png()), **extra})

    def test_gate_post_and_upload(self):
        self.assertRedirects(self.client.get(reverse('central_dashboard')), reverse('onboarding'))
        self.assertEqual(self.client.post(reverse('create_department'), {'name': 'Blocked'}).status_code, 403)
        self.assertFalse(Department.objects.exists())
        self.assertRedirects(self.upload(), reverse('central_dashboard'))
        self.user.refresh_from_db()
        self.assertTrue(signature_valid(self.user))
        self.assertFalse(Membership.objects.exists())
        response = self.client.get(reverse('signature_preview'))
        self.assertEqual(response.status_code, 200)
        image = Image.open(BytesIO(response.content))
        self.assertEqual(image.size, (600, 200))
        self.assertEqual(image.getpixel((285, 95)), (0, 0, 0, 255))
        self.assertEqual(image.getpixel((284, 95)), (255, 255, 255, 255))
        self.assertContains(self.client.get(reverse('onboarding')), 'Your signature')
        self.assertNotContains(self.client.get(reverse('onboarding')), 'type="file"')
        self.client.logout()
        self.assertEqual(self.client.get(reverse('signature_preview')).status_code, 302)

    def test_png_rejections_and_large_input(self):
        from django.core.exceptions import ValidationError
        jpeg = BytesIO(); Image.new('RGB', (10, 10)).save(jpeg, 'JPEG')
        animated = BytesIO()
        Image.new('RGBA', (10, 10), 'black').save(animated, 'PNG', save_all=True,
            append_images=[Image.new('RGBA', (10, 10), 'white')], duration=10)
        for data in (b'bad', png()[:30], jpeg.getvalue(), b'x' * 2097153,
                     png((4097, 1)), animated.getvalue()):
            with self.subTest(size=len(data)), self.assertRaises(ValidationError):
                normalize(SimpleUploadedFile('x.png', data))
        output = normalize(SimpleUploadedFile('x.png', png((3000, 1000))))
        self.assertEqual(Image.open(BytesIO(output)).size, (600, 200))

    def test_existing_validation_cache_and_changes(self):
        self.upload()
        self.user.refresh_from_db()
        with patch('accounts.signatures.decode_png') as decode:
            self.assertTrue(signature_valid(self.user))
            decode.assert_not_called()
        with self.user.signature_image.storage.open(self.user.signature_image.name, 'wb') as stream:
            stream.write(b'corrupt')
        self.assertFalse(signature_valid(self.user))
        self.assertEqual(self.client.get(reverse('signature_preview')).status_code, 404)

    def test_username_confirmation_and_privacy(self):
        self.user.username_confirmation_required = True
        self.user.save(update_fields=['username_confirmation_required'])
        User.objects.create_user(username='taken')
        self.assertContains(self.upload(username='taken'), 'already in use')
        self.assertContains(self.upload(username='bad name'), 'valid username')
        self.assertRedirects(self.upload(username='selected'), reverse('central_dashboard'))
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'selected')
        self.assertFalse(self.user.username_confirmation_required)
        other = User.objects.create_user(username='other')
        self.client.force_login(other)
        self.assertEqual(self.client.get(reverse('signature_preview')).status_code, 404)

    def test_admin_exempt_staff_gated(self):
        for flag in ('is_admin', 'is_superuser', 'is_staff'):
            user = User.objects.create_user(username=flag, **{flag: True})
            self.client.force_login(user)
            response = self.client.get(reverse('routing_view'))
            self.assertEqual(response.url, reverse('onboarding' if flag == 'is_staff' else 'admin_dashboard'))

    def test_storage_failure_and_no_cryptographic_changes(self):
        before = (self.user.private_key, self.user.public_key)
        with patch('accounts.signatures.SignatureStorage.save', side_effect=OSError):
            self.assertContains(self.upload(), 'Could not save')
        self.user.refresh_from_db()
        self.assertFalse(signature_valid(self.user))
        self.assertEqual((self.user.private_key, self.user.public_key), before)

    def test_new_google_persisted_marker(self):
        from allauth.socialaccount.models import SocialLogin, SocialAccount
        from .adapter import OnboardingSocialAdapter
        social = SocialLogin(user=User(username='suggested'), account=SocialAccount(provider='google', uid='test'))
        from django.test import RequestFactory
        with patch('allauth.socialaccount.adapter.DefaultSocialAccountAdapter.save_user', return_value=social.user):
            OnboardingSocialAdapter().save_user(RequestFactory().get('/'), social)
        self.assertTrue(social.user.username_confirmation_required)

    def test_transparent_padding_and_metadata(self):
        from PIL.PngImagePlugin import PngInfo
        image = Image.new('RGBA', (100, 100), (0, 0, 0, 0))
        image.paste((0, 0, 0, 255), (40, 45, 60, 55))
        data = BytesIO(); info = PngInfo(); info.add_text('private', 'metadata')
        image.save(data, 'PNG', pnginfo=info)
        result = Image.open(BytesIO(normalize(SimpleUploadedFile('x.png', data.getvalue()))))
        self.assertEqual(result.size, (600, 200))
        self.assertEqual(result.getbbox(), (290, 95, 310, 105))
        self.assertNotIn('private', result.info)

    def test_invitation_resume_and_explicit_acceptance(self):
        from allauth.account.models import EmailAddress
        from .models import Invitation
        department = Department.objects.create(name='Invited')
        invitation = Invitation.objects.create(department=department, inviter=self.user, email='owned@example.com')
        EmailAddress.objects.create(user=self.user, email=invitation.email, verified=True)
        session = self.client.session
        session['pending_invite_token'] = invitation.token
        session['invite_verification_intent'] = [invitation.token, self.user.pk]
        session.save()
        target = reverse('accept_invitation', args=[invitation.token])
        self.assertEqual(self.client.post(target).status_code, 403)
        self.assertRedirects(self.upload(), target)
        invitation.refresh_from_db()
        self.assertFalse(invitation.accepted)
        self.assertFalse(Membership.objects.exists())
        self.assertRedirects(self.client.post(target), reverse('department_dashboard', args=[department.pk]))
