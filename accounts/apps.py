from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = 'accounts'

    def ready(self):
        from . import invitation_signals  # noqa: F401
        from . import department_deletion  # noqa: F401
