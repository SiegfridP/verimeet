"""Private R2 adapter. No URLs, deletion, overwrite, or filesystem fallback."""
import re
from io import BytesIO

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.files.base import File


class DurablePrivateMixin:
    evidence_prefix = 'profiles'

    def object_key(self, name):
        pattern = (r'[0-9a-f]{32}\.png' if self.evidence_prefix == 'snapshots'
                   else r'(?:normalized/[0-9a-f]{32}|signatures/[A-Za-z0-9_-]+)\.png')
        if not re.fullmatch(pattern, name):
            raise PermissionDenied('Invalid private object identifier.')
        return self.evidence_prefix + '/' + name

    def client(self):
        import boto3
        from botocore.config import Config
        return boto3.client('s3', endpoint_url=settings.EVIDENCE_ENDPOINT,
                            region_name='auto',
                            aws_access_key_id=settings.EVIDENCE_ACCESS_KEY_ID,
                            aws_secret_access_key=settings.EVIDENCE_SECRET_ACCESS_KEY,
                            config=Config(signature_version='s3v4', connect_timeout=5,
                                          read_timeout=20, retries={'max_attempts': 2},
                                          request_checksum_calculation='when_required',
                                          response_checksum_validation='when_required'))

    def _save(self, name, content):
        if not settings.DURABLE_EVIDENCE:
            return super()._save(name, content)
        data = content.read(2097153)
        if len(data) > 2097152:
            raise ValueError('Private object too large.')
        self.client().put_object(Bucket=settings.EVIDENCE_BUCKET, Key=self.object_key(name),
                                 Body=data, ContentType='image/png', IfNoneMatch='*')
        return name

    def _open(self, name, mode='rb'):
        if not settings.DURABLE_EVIDENCE:
            return super()._open(name, mode)
        if mode != 'rb':
            raise PermissionDenied('Read-only private object access.')
        response = self.client().get_object(Bucket=settings.EVIDENCE_BUCKET, Key=self.object_key(name))
        body = response['Body']
        try:
            data = body.read(2097153)
        finally:
            body.close()
        if len(data) > 2097152:
            raise ValueError('Private object too large.')
        return File(BytesIO(data), name=name)

    def exists(self, name):
        if not settings.DURABLE_EVIDENCE:
            return super().exists(name)
        from botocore.exceptions import ClientError
        try:
            self.client().head_object(Bucket=settings.EVIDENCE_BUCKET, Key=self.object_key(name))
            return True
        except ClientError as error:
            if error.response['Error']['Code'] in ('404', 'NoSuchKey'):
                return False
            raise

    def get_available_name(self, name, max_length=None):
        if not settings.DURABLE_EVIDENCE:
            return super().get_available_name(name, max_length)
        self.object_key(name)
        if max_length is not None and len(name) > max_length:
            raise ValueError('Private identifier too long.')
        return name  # Atomic conditional PUT rejects collisions; never rename evidence.

    def path(self, name):
        if settings.DURABLE_EVIDENCE:
            raise NotImplementedError('Private objects have no filesystem path.')
        return super().path(name)
