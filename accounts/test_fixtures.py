"""Explicit, isolated initial signature uploads for regression request actors."""
from tempfile import TemporaryDirectory

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings

from .test_onboarding import png


def signature_storage(test):
    directory = TemporaryDirectory()
    test.addCleanup(directory.cleanup)
    settings = override_settings(PRIVATE_SIGNATURE_ROOT=directory.name)
    settings.enable()
    test.addCleanup(settings.disable)


def complete_onboarding(*users):
    for user in users:
        user.signature_image.save('signature.png', SimpleUploadedFile('signature.png', png()))
