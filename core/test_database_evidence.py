from hashlib import sha256
from unittest.mock import patch
from django.core.exceptions import PermissionDenied
from django.core.files.base import ContentFile
from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from accounts.signatures import SignatureStorage
from accounts.test_onboarding import png
from meetings.evidence_objects import PrivateEvidenceObject
from meetings.visual_evidence import SnapshotStorage, read_snapshot
from meetings.models import SigningVisualSnapshot, AuditLog


class DatabaseProductionSettingsTests(SimpleTestCase):
    def test_database_backend_starts_without_r2_and_keeps_production_guards(self):
        from core.test_deployment import ProductionCredentialTests
        config = ProductionCredentialTests().settings_for(EVIDENCE_BACKEND='database',
            EVIDENCE_ENDPOINT=None, EVIDENCE_BUCKET=None, EVIDENCE_ACCESS_KEY_ID=None,
            EVIDENCE_SECRET_ACCESS_KEY=None)
        self.assertTrue(config['PRODUCTION'])
        self.assertTrue(config['DURABLE_EVIDENCE'])
        self.assertTrue(config['SESSION_COOKIE_SECURE'])
        self.assertEqual(config['DATABASES']['default']['ENGINE'], 'django.db.backends.postgresql')


@override_settings(DURABLE_EVIDENCE=True, EVIDENCE_BACKEND='database')
class DatabaseEvidenceTests(TestCase):
    def test_concrete_stores_collision_integrity_and_retention(self):
        for store in (SignatureStorage(), SnapshotStorage()):
            with self.subTest(storage=type(store).__name__), patch.object(store, 'client', side_effect=AssertionError('No network')):
                name = store.save('a' * 32 + '.png', ContentFile(png(), name='test.png'))
                self.assertTrue(store.exists(name))
                with store.open(name, 'rb') as stream:
                    original = stream.read()
                with self.assertRaises(IntegrityError):
                    store._save(name, ContentFile(b'replacement'))
                with store.open(name, 'rb') as stream:
                    self.assertEqual(stream.read(), original)
                obj = PrivateEvidenceObject.objects.get(pk=store.object_key(name))
                self.assertEqual(obj.content_sha256, sha256(original).hexdigest())
                obj.data = b'changed'
                for operation in (obj.save, obj.delete,
                                  lambda: PrivateEvidenceObject.objects.filter(pk=obj.pk).update(data=b'bad'),
                                  lambda: PrivateEvidenceObject.objects.filter(pk=obj.pk).delete(),
                                  lambda: store.delete(name), lambda: store.url(name)):
                    with self.assertRaises((PermissionDenied, NotImplementedError)):
                        operation()
                with self.assertRaises(NotImplementedError):
                    store.path(name)
                with patch.object(PrivateEvidenceObject.objects, 'using', side_effect=RuntimeError('database unavailable')):
                    with self.assertRaises(RuntimeError):
                        store.open(name, 'rb')

    def test_outer_transaction_rolls_back_bytes(self):
        store = SnapshotStorage()
        name = 'b' * 32 + '.png'
        with self.assertRaises(RuntimeError), transaction.atomic():
            store.save(name, ContentFile(png()))
            raise RuntimeError('abort')
        self.assertFalse(store.exists(name))

    def test_legacy_read_and_hash_mismatch_fail_closed(self):
        data = png()
        PrivateEvidenceObject.objects.create(key='profiles/signatures/legacy.png', data=data,
                                             content_sha256=sha256(data).hexdigest())
        with SignatureStorage().open('signatures/legacy.png', 'rb') as stream:
            self.assertEqual(stream.read(), data)
        name = SnapshotStorage().save('c' * 32 + '.png', ContentFile(data))
        self.assertIsNone(read_snapshot(name, '0' * 64, len(data), 1, 1))
        with self.assertRaises(PermissionDenied):
            SignatureStorage().open('../escape', 'rb')


class DatabaseSigningTests(TestCase):
    from meetings.test_visual_evidence import VisualEvidenceTests as _Fixture
    setUp = _Fixture.setUp
    sign = _Fixture.sign

    def test_real_database_capture_rollback_and_success(self):
        with self.user.signature_image.open('rb') as stream:
            original = stream.read()
        with override_settings(DURABLE_EVIDENCE=True, EVIDENCE_BACKEND='database'):
            PrivateEvidenceObject.objects.create(key='profiles/' + self.user.signature_image.name,
                data=original, content_sha256=sha256(original).hexdigest())
            with patch('meetings.visual_evidence.read_snapshot', return_value=None):
                self.assertEqual(self.sign().status_code, 400)
            self.att.refresh_from_db()
            self.assertFalse(self.att.has_signed)
            self.assertFalse(self.att.cryptographic_signature)
            self.assertFalse(SigningVisualSnapshot.objects.exists())
            self.assertFalse(PrivateEvidenceObject.objects.filter(pk__startswith='snapshots/').exists())
            self.assertFalse(AuditLog.objects.filter(event_type='signature.created').exists())
            self.assertEqual(self.sign().status_code, 302)
            snapshot = SigningVisualSnapshot.objects.get(attendance=self.att)
            self.assertEqual(read_snapshot(snapshot.storage_identifier, snapshot.content_sha256,
                snapshot.byte_length, snapshot.width, snapshot.height), original)
            self.assertEqual(self.sign().status_code, 403)
