from django.apps import AppConfig


class MeetingsConfig(AppConfig):
    name = 'meetings'

    def ready(self):
        from . import deletion_guards  # noqa: F401 -- register collector-safe guard
