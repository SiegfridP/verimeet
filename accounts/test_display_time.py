from datetime import datetime
from types import SimpleNamespace

from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.utils import timezone

from core.display_time import format_pht_datetime


class PhilippineTimeTests(SimpleTestCase):
    def test_aware_conversion_in_utc_context(self):
        with timezone.override("UTC"):
            for source, expected in (
                ("2026-11-29T02:47:12.737582+00:00", "11/29/26, 10:47 AM PHT"),
                ("2026-11-29T16:00:00+00:00", "11/30/26, 12:00 AM PHT"),
                ("2026-11-29T04:00:00+00:00", "11/29/26, 12:00 PM PHT"),
            ):
                with self.subTest(source=source):
                    self.assertEqual(format_pht_datetime(datetime.fromisoformat(source)), expected)

    def test_invitation_displays_preserve_machine_datetime(self):
        expiry = datetime.fromisoformat("2026-11-29T02:47:12.737582+00:00")
        department = SimpleNamespace(name="Engineering")
        invitation = SimpleNamespace(expires_at=expiry, department=department, token="test-token")
        context = {
            "invitation": invitation,
            "department": department,
            "pending_invitations": [invitation],
            "acceptance_url": "https://example.test/invite/test-token/",
        }
        with timezone.override("UTC"):
            for name in ("_invitation_cards.html", "accept_invitation.html",
                         "invitation_email.html", "invitation_email.txt"):
                with self.subTest(template=name):
                    html = render_to_string(f"accounts/{name}", context)
                    self.assertIn("11/29/26, 10:47 AM PHT", html)
                    if name == "_invitation_cards.html":
                        self.assertIn(f'datetime="{expiry.isoformat()}"', html)
        self.assertEqual(invitation.expires_at, expiry)
