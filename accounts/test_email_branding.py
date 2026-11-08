from pathlib import Path
from html import unescape
from types import SimpleNamespace
from django.test import TestCase, TransactionTestCase, RequestFactory, override_settings
from django.template.loader import get_template
from django.core import mail
from allauth.account import app_settings
from allauth.core.context import request_context
from allauth.account.adapter import get_adapter
from allauth.account.internal.flows.password_reset import request_password_reset
from allauth.account.models import EmailAddress
from .models import User, Department, Invitation, InvitationDelivery
from .invitation_delivery import process_one


@override_settings(MAILERS={'default': {'BACKEND': 'django.core.mail.backends.locmem.EmailBackend'}},
                   DEFAULT_FROM_EMAIL='VeriMeet <configured@example.invalid>')
class EmailBrandingTests(TestCase):
    variants = {
        'email_confirmation_signup': ('Confirm your email to get started', 'activate_url'),
        'email_confirmation': ('Confirm your email address', 'activate_url'),
        'password_reset_key': ('Reset your password', 'password_reset_url'),
        'unknown_account': ('Account recovery options', 'signup_url'),
        'account_already_exists': ('Recover your existing account', 'password_reset_url'),
    }

    def test_active_overrides_multipart_sender_subject_and_privacy(self):
        request = RequestFactory().get('/', HTTP_HOST='testserver')
        for name, (subject, variable) in self.variants.items():
            with self.subTest(name=name), request_context(request):
                for suffix in ('subject.txt', 'message.txt', 'message.html'):
                    origin = Path(get_template(f'account/email/{name}_{suffix}').origin.name)
                    self.assertTrue(origin.is_relative_to(Path(__file__).parent / 'templates'))
                url = 'https://testserver/action/?value=one&other=two'
                message = get_adapter().render_mail('account/email/' + name, 'one@example.invalid', {
                    variable: url, 'user': SimpleNamespace(username='PRIVATE_USERNAME', pk=987654),
                    'username': 'PRIVATE_USERNAME', 'email': 'PRIVATE_ADDRESS',
                })
                self.assertEqual(message.subject, 'VeriMeet — ' + subject)
                self.assertEqual(message.from_email, 'VeriMeet <configured@example.invalid>')
                self.assertEqual(message.to, ['one@example.invalid'])
                self.assertEqual(len(message.alternatives), 1)
                html, mimetype = message.alternatives[0]
                self.assertEqual(mimetype, 'text/html')
                self.assertIn(url, message.body)
                self.assertIn(url, unescape(html))
                self.assertIn('&amp;other', html)
                for body in (message.body, html):
                    self.assertNotIn('PRIVATE_', body)
                    self.assertNotIn('987654', body)
                    self.assertIn('automated notification', body)

    def test_password_reset_flow_retains_valid_link(self):
        user = User.objects.create_user(username='PRIVATE_USERNAME', email='owner@example.invalid', password='test-password')
        EmailAddress.objects.create(user=user, email=user.email, verified=True)
        request = RequestFactory().get('/', HTTP_HOST='testserver')
        with request_context(request):
            request_password_reset(request, user.email, [user], None)
        message = mail.outbox[0]
        import re
        link = re.search(r'https?://[^\s]+', message.body).group()
        key = link.rstrip('/').rsplit('/', 1)[-1]
        # Allauth reset URL contains the user id followed by the standard token.
        token = key.split('-', 1)[1]
        self.assertTrue(app_settings.PASSWORD_RESET_TOKEN_GENERATOR().check_token(user, token))
        self.assertIn(link, unescape(message.alternatives[0].content))
        self.assertNotIn(user.username, message.body)


@override_settings(MAILERS={'default': {'BACKEND': 'django.core.mail.backends.locmem.EmailBackend'}},
                   DEFAULT_FROM_EMAIL='VeriMeet <configured@example.invalid>')
class InvitationBrandingTests(TransactionTestCase):
    def test_real_message_construction_and_escaping(self):
        user = User.objects.create_user(username='PRIVATE_USERNAME')
        department = Department.objects.create(name='<script>alert("x")</script> & Team')
        invitation = Invitation.objects.create(department=department, inviter=user, email='owner@example.invalid')
        row = InvitationDelivery.objects.create(invitation=invitation)
        self.assertEqual(process_one(row.pk, 'https://testserver'), 'submitted')
        message = mail.outbox[0]
        self.assertEqual(message.subject, 'VeriMeet — Officer invitation')
        self.assertEqual(message.from_email, 'VeriMeet <configured@example.invalid>')
        self.assertEqual(message.to, [invitation.email])
        html = message.alternatives[0].content
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)
        from django.urls import reverse
        url = 'https://testserver' + reverse('accept_invitation', args=[invitation.token])
        for body in (message.body, html):
            self.assertIn(url, body)
            self.assertIn('seven days', body)
            self.assertNotIn(user.username, body)


    def test_plain_text_department_cannot_inject_message_sections(self):
        from django.template.loader import render_to_string
        from django.utils import timezone
        name = 'Team\r\n\r\nBcc: forged@example.invalid\x00\x1b\u0085\u2028\u2029\u202eExtra instructions'
        url = 'https://testserver/invitation/?a=one&b=two'
        body = render_to_string('accounts/invitation_email.txt', {
            'department': SimpleNamespace(name=name),
            'invitation': SimpleNamespace(expires_at=timezone.now()),
            'acceptance_url': url,
        })
        invitation_line = next(line for line in body.splitlines() if line.startswith('You are invited'))
        self.assertIn('Team Bcc: forged@example.invalid Extra instructions as an Officer.', invitation_line)
        self.assertNotIn('\nBcc:', body)
        for control in ('\r', '\x00', '\x1b', '\u0085', '\u2028', '\u2029', '\u202e'):
            self.assertNotIn(control, body)
        self.assertIn(url, body)
        self.assertNotIn('&amp;', body)
