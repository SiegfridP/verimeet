import os
import runpy
from io import BytesIO
from hashlib import sha256
from unittest.mock import Mock, patch
from django.core.exceptions import PermissionDenied
from django.core.files.base import ContentFile
from django.core.mail import EmailMultiAlternatives
from django.test import SimpleTestCase, TestCase, override_settings
from core.private_storage import DurablePrivateMixin
from core.resend_backend import EmailBackend
from core.email_config import email_settings


@override_settings(DURABLE_EVIDENCE=True, EVIDENCE_BUCKET='test-private')
class EvidenceTests(SimpleTestCase):
    def test_conditional_write_preserves_identifier(self):
        store = DurablePrivateMixin()
        client = Mock()
        name = 'normalized/' + 'a' * 32 + '.png'
        with patch.object(store, 'client', return_value=client):
            self.assertEqual(store._save(name, ContentFile(b'png')), name)
        self.assertEqual(client.put_object.call_args.kwargs['IfNoneMatch'], '*')
        self.assertEqual(client.put_object.call_args.kwargs['Key'], 'profiles/' + name)

    def test_traversal_and_cross_namespace_rejected(self):
        store = DurablePrivateMixin()
        for name in ('../secret', '/secret', 'normalized/../../secret', 'a.png', 'signatures/a/b.png'):
            with self.assertRaises(PermissionDenied):
                store.object_key(name)

    def test_bounded_read_closes_body(self):
        store = DurablePrivateMixin()
        body = Mock()
        body.read.return_value = b'x' * 2097153
        client = Mock()
        client.get_object.return_value = {'Body': body}
        with patch.object(store, 'client', return_value=client), self.assertRaises(ValueError):
            store._open('normalized/' + 'a' * 32 + '.png')
        body.close.assert_called_once()


@override_settings(RESEND_API_KEY='test-only', RESEND_TIMEOUT=20)
class ResendTests(SimpleTestCase):
    def test_acceptance_required_and_html_preserved(self):
        message = EmailMultiAlternatives('subject', 'text', 'sender@test.invalid', ['recipient@test.invalid'])
        message.attach_alternative('<p>text</p>', 'text/html')
        response = Mock(status=200)
        response.read.return_value = b'{"id":"accepted"}'
        with patch('core.resend_backend.urlopen') as send:
            send.return_value.__enter__.return_value = response
            self.assertEqual(EmailBackend().send_messages([message]), 1)
            self.assertIn(b'"html"', send.call_args.args[0].data)
            response.read.return_value = b'{}'
            with self.assertRaisesRegex(RuntimeError, '^Email provider submission failed.$'):
                EmailBackend().send_messages([message])

    def test_https_production_config(self):
        config = email_settings(dict(DJANGO_ENV='production', EMAIL_BACKEND='core.resend_backend.EmailBackend',
            RESEND_API_KEY='re_' + 'aB9x' * 8, DEFAULT_FROM_EMAIL='sender@verimeet.test', APPLICATION_ORIGIN='https://verimeet.test'))
        self.assertTrue(config['EMAIL_PRODUCTION'])


class DatabaseConfigurationTests(SimpleTestCase):
    def settings_for(self, **values):
        env = dict(DJANGO_SECRET_KEY='test-only', DJANGO_ENV='development', **values)
        with patch('os.environ', env), patch('dotenv.load_dotenv'):
            return runpy.run_module('core.settings')

    def test_sqlite_development_and_postgres_url(self):
        self.assertEqual(self.settings_for()['DATABASES']['default']['ENGINE'], 'django.db.backends.sqlite3')
        db = self.settings_for(DATABASE_URL='postgresql://test:test@localhost/test')['DATABASES']['default']
        self.assertEqual(db['ENGINE'], 'django.db.backends.postgresql')
        self.assertTrue(db['CONN_HEALTH_CHECKS'])

    def test_invalid_url_rejected(self):
        from django.core.exceptions import ImproperlyConfigured
        with self.assertRaises(ImproperlyConfigured):
            self.settings_for(DATABASE_URL='sqlite:///unsafe.db')


class ProductionCredentialTests(SimpleTestCase):
    secret = 'rT8!mQ2@vN9#kL4$zP7%aB3^cD6&eF0*gH5(iJ1)uW8_xY2+oS'

    def settings_for(self, **changes):
        env = dict(DJANGO_ENV='production', DJANGO_DEBUG='False', DJANGO_SECRET_KEY=self.secret,
            DATABASE_URL='postgresql://test:test@localhost/test', DJANGO_ALLOWED_HOSTS='verimeet.test',
            APPLICATION_ORIGIN='https://verimeet.test', EMAIL_BACKEND='core.resend_backend.EmailBackend',
            RESEND_API_KEY='re_' + 'aB9x' * 8, DEFAULT_FROM_EMAIL='sender@verimeet.test',
            GOOGLE_CLIENT_ID='123456.apps.googleusercontent.com', GOOGLE_CLIENT_SECRET='GOCSPX-synthetic-credential',
            EVIDENCE_ENDPOINT='https://' + 'a' * 32 + '.r2.cloudflarestorage.com', EVIDENCE_BUCKET='test',
            EVIDENCE_ACCESS_KEY_ID='synthetic', EVIDENCE_SECRET_ACCESS_KEY='synthetic',
            SIGNING_KEY_ENCRYPTION_KEY='YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=')
        env.update(changes)
        env = {key: value for key, value in env.items() if value is not None}
        with patch('os.environ', env), patch('dotenv.load_dotenv'):
            return runpy.run_module('core.settings')

    def test_valid_production_including_punctuation_and_https_security(self):
        config = self.settings_for()
        self.assertTrue(config['DURABLE_EVIDENCE'])
        for name in ('SECURE_SSL_REDIRECT', 'SESSION_COOKIE_SECURE', 'CSRF_COOKIE_SECURE'):
            self.assertTrue(config[name])
        self.assertEqual(config['CSRF_TRUSTED_ORIGINS'], ['https://verimeet.test'])

    def test_invalid_production_credentials_are_sanitized(self):
        from django.core.exceptions import ImproperlyConfigured
        cases = {
            'DJANGO_SECRET_KEY': (None, '', ' ', 'YOUR_SECRET_KEY_HERE', 'x' * 60, 'short',
                                  'django-insecure-' + self.secret, self.secret + '\n', self.secret + '\x7f'),
            'GOOGLE_CLIENT_ID': (None, '', ' ', 'YOUR_GOOGLE_CLIENT_ID_HERE', 'replace-with-client-id', 'id\n', 'id\u0085'),
            'GOOGLE_CLIENT_SECRET': (None, '', ' ', 'YOUR_GOOGLE_CLIENT_SECRET_HERE', 'secret\x00'),
            'RESEND_API_KEY': (None, '', ' ', 'YOUR_API_KEY_HERE', 're_placeholder123456789012345',
                               're_short', 'not-a-key', 're_' + 'a' * 25 + '\n'),
        }
        for name, values in cases.items():
            for value in values:
                with self.subTest(name=name, value_index=values.index(value)):
                    with self.assertRaises(ImproperlyConfigured) as caught:
                        self.settings_for(**{name: value})
                    self.assertIn(name, str(caught.exception))
                    if value and value.strip():
                        self.assertNotIn(value, str(caught.exception))

    def test_development_placeholder_behavior_unchanged(self):
        with patch.dict(os.environ, {'DJANGO_ENV': 'development', 'DJANGO_SECRET_KEY': 'test-only'}, clear=True), patch('dotenv.load_dotenv'):
            config = runpy.run_module('core.settings')
        self.assertFalse(config['DURABLE_EVIDENCE'])


class FakePrivateObjects:
    """In-memory conditional object API; never constructs a provider client."""
    def __init__(self):
        self.objects = {}
        self.failure = None
        self.corrupt = False

    def put_object(self, **request):
        from botocore.exceptions import ClientError
        key = request['Key']
        if self.failure and key.startswith('snapshots/'):
            raise self.failure
        assert request['IfNoneMatch'] == '*'
        if key in self.objects:
            raise ClientError({'Error': {'Code': 'PreconditionFailed'},
                               'ResponseMetadata': {'HTTPStatusCode': 412}}, 'PutObject')
        self.objects[key] = request['Body']

    def get_object(self, **request):
        key = request['Key']
        data = self.objects[key]
        if self.corrupt and key.startswith('snapshots/'):
            data = b'corrupt'
        return {'Body': BytesIO(data)}


@override_settings(DURABLE_EVIDENCE=True, EVIDENCE_BUCKET='test-private')
class ConcreteStorageTests(SimpleTestCase):
    def test_concrete_creation_readback_and_guards(self):
        from accounts.signatures import SignatureStorage
        from accounts.test_onboarding import png
        from meetings.visual_evidence import SnapshotStorage
        from botocore.exceptions import ClientError
        for store in (SignatureStorage(), SnapshotStorage()):
            fake = FakePrivateObjects()
            name = 'a' * 32 + '.png'
            with self.subTest(storage=type(store).__name__), patch.object(store, 'client', return_value=fake):
                stored = store.save(name, ContentFile(png(), name='signature.png'))
                with store.open(stored, 'rb') as stream:
                    data = stream.read()
                self.assertEqual(data, fake.objects[store.object_key(stored)])
                with self.assertRaises(ClientError):
                    store._save(stored, ContentFile(b'replacement'))
                if isinstance(store, SnapshotStorage):
                    with self.assertRaises(ClientError):
                        store.save(stored, ContentFile(png()))
                self.assertEqual(fake.objects[store.object_key(stored)], data)
                with self.assertRaises(PermissionDenied):
                    store.delete(stored)
                with self.assertRaises((PermissionDenied, NotImplementedError)):
                    store.url(stored)
                with self.assertRaises(NotImplementedError):
                    store.path(stored)
                with patch.object(fake, 'put_object', side_effect=OSError('unavailable')):
                    with self.assertRaises(OSError):
                        store.save(name, ContentFile(png(), name='signature.png'))
                with patch.object(fake, 'get_object', side_effect=OSError('unavailable')):
                    with self.assertRaises(OSError):
                        store.open(stored, 'rb')


class ProductionSigningStorageTests(TestCase):
    from meetings.test_visual_evidence import VisualEvidenceTests as _Fixture
    setUp = _Fixture.setUp
    sign = _Fixture.sign

    def test_production_signing_storage_failure_and_readback_rollback(self):
        from meetings.models import SigningVisualSnapshot, AuditLog, QRUsage
        from meetings.visual_evidence import read_snapshot
        with self.user.signature_image.open('rb') as stream:
            original = stream.read()
        fake = FakePrivateObjects()
        fake.objects['profiles/' + self.user.signature_image.name] = original
        with override_settings(DURABLE_EVIDENCE=True, EVIDENCE_BUCKET='test-private'), patch.object(DurablePrivateMixin, 'client', return_value=fake):
            for failure, corrupt in ((OSError('private service details'), False), (None, True)):
                fake.failure, fake.corrupt = failure, corrupt
                with self.subTest(unavailable=failure is not None):
                    response = self.sign()
                    self.assertEqual(response.status_code, 400)
                    self.assertNotContains(response, 'private service details', status_code=400)
                    self.att.refresh_from_db()
                    self.assertFalse(self.att.has_signed)
                    self.assertFalse(self.att.cryptographic_signature)
                    self.assertFalse(SigningVisualSnapshot.objects.exists())
                    self.assertFalse(QRUsage.objects.exists())
                    self.assertFalse(AuditLog.objects.filter(event_type='signature.created').exists())
            fake.failure, fake.corrupt = None, False
            self.assertEqual(self.sign().status_code, 302)
            snapshot = SigningVisualSnapshot.objects.get(attendance=self.att)
            self.assertEqual(snapshot.content_sha256, sha256(original).hexdigest())
            self.assertEqual(read_snapshot(snapshot.storage_identifier, snapshot.content_sha256,
                snapshot.byte_length, snapshot.width, snapshot.height), original)
            self.assertEqual(self.sign().status_code, 403)
            self.assertEqual(SigningVisualSnapshot.objects.count(), 1)
