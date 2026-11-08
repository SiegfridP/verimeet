from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, RequestFactory, override_settings
from allauth.account.adapter import get_adapter
from allauth.core.context import request_context
from core.email_config import email_settings, origin


class EmailConfigTests(SimpleTestCase):
    def production(self):
        return dict(DJANGO_ENV='production', EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend',
                    EMAIL_HOST='smtp.mail.test', EMAIL_HOST_USER='smtp-user', EMAIL_HOST_PASSWORD='test-only-secret',
                    DEFAULT_FROM_EMAIL='mail@verimeet.test', APPLICATION_ORIGIN='https://verimeet.test')

    def test_development_defaults(self):
        config = email_settings({})
        self.assertFalse(config['EMAIL_PRODUCTION'])
        self.assertIn('console', config['MAILERS']['default']['BACKEND'])

    def test_valid_production_and_ssl(self):
        env = self.production()
        config = email_settings(env)
        self.assertEqual(config['DEFAULT_FROM_EMAIL'], 'VeriMeet <mail@verimeet.test>')
        self.assertEqual(config['MAILERS']['default']['OPTIONS']['timeout'], 20)
        env.update(EMAIL_USE_TLS='false', EMAIL_USE_SSL='true', EMAIL_PORT='465', EMAIL_TIMEOUT='30')
        self.assertTrue(email_settings(env)['MAILERS']['default']['OPTIONS']['use_ssl'])

    def test_invalid_production_settings_are_sanitized(self):
        cases = dict(EMAIL_BACKEND='django.core.mail.backends.console.EmailBackend',
                     EMAIL_HOST='smtp.example.invalid', EMAIL_HOST_USER='', EMAIL_HOST_PASSWORD='YOUR_PASSWORD',
                     DEFAULT_FROM_EMAIL='VeriMeet <noreply@example.invalid>', EMAIL_FROM_NAME='bad\r\nBcc: x',
                     EMAIL_PORT='not-a-port', EMAIL_TIMEOUT='120', EMAIL_USE_TLS='false',
                     EMAIL_USE_SSL='true', APPLICATION_ORIGIN='http://verimeet.test', DJANGO_ENV='prod')
        for key, value in cases.items():
            with self.subTest(key=key):
                env = self.production(); env[key] = value
                with self.assertRaises(ImproperlyConfigured) as error:
                    email_settings(env)
                self.assertNotIn('test-only-secret', str(error.exception))
                self.assertNotIn('smtp-user', str(error.exception))

    def test_malformed_smtp_values(self):
        for key, value in (('EMAIL_HOST', 'smtp.test\\bad'), ('EMAIL_HOST', 'smtp.test\n'),
                           ('EMAIL_HOST_PASSWORD', 'private\r\nvalue'), ('EMAIL_TIMEOUT', 'nan')):
            env = self.production(); env[key] = value
            with self.subTest(key=key), self.assertRaises(ImproperlyConfigured):
                email_settings(env)

    def test_malformed_origins(self):
        for value in ('', 'http://host.test', 'https://user:pass@host.test', 'https://host.test/path',
                      'https://host.test?', 'https://host.test#', 'https://host.test:bad',
                      'https://host.test:', 'https://host.test\n', 'https://host.test\\evil',
                      'https://bad..test', 'https://host.test:65536'):
            with self.subTest(value=value), self.assertRaises(ImproperlyConfigured):
                origin(value, True)
        self.assertEqual(origin('https://host.test/'), 'https://host.test')

    @override_settings(EMAIL_PRODUCTION=True, APPLICATION_ORIGIN='https://canonical.test')
    def test_workers_accept_only_canonical_https_origin(self):
        from accounts.invitation_delivery import validate_configuration as invitation
        from accounts.verification_delivery import validate_configuration as verification
        for validate in (invitation, verification):
            validate('https://canonical.test')
            for supplied in ('https://different.test', 'http://canonical.test'):
                with self.assertRaises(ImproperlyConfigured):
                    validate(supplied)

    @override_settings(EMAIL_PRODUCTION=True, APPLICATION_ORIGIN='https://canonical.test', ALLOWED_HOSTS=['other.test'])
    def test_account_mail_uses_canonical_links_and_preserves_tokens(self):
        request = RequestFactory().get('/', HTTP_HOST='testserver')
        for prefix, variable in (('password_reset_key', 'password_reset_url'),
                                 ('unknown_account', 'signup_url'),
                                 ('account_already_exists', 'password_reset_url'),
                                 ('email_confirmation', 'activate_url'),
                                 ('email_confirmation_signup', 'activate_url')):
            with self.subTest(prefix=prefix), request_context(request):
                message = get_adapter().render_mail('account/email/' + prefix, 'owner@recipient.test', {
                    variable: 'http://other.test/action/unchanged-token/?x=1&y=2'})
                self.assertIn('https://canonical.test/action/unchanged-token/?x=1&y=2', message.body)
                self.assertNotIn('other.test', message.body)
                self.assertNotIn('other.test', message.alternatives[0].content)

    @override_settings(APPLICATION_ORIGIN='https://canonical.test', ALLOWED_HOSTS=['app.test', '*'])
    def test_invalid_source_links_fail_closed(self):
        invalid = (
            'https://external.test/path/SECRET', '//app.test/path',
            'https://user:SECRET@app.test/path', 'https://app.test:bad/path',
            'https://app.test:65536/path', 'https://app.test:0/path',
            'https://app.test:/path', 'https:///path', 'not-a-url',
            'ftp://app.test/path', 'https://app.test/path#fragment', 'https://app.test/path#',
            'https://app.test/path\n', 'https://app.test/\x00path',
            'https://app.test/\u202epath', 'https://app.test/invalid%escape',
            'https://app.test/%0d%0aInjected', 'https://app.test\\external.test/path',
        )
        for production in (False, True):
            for url in invalid:
                with self.subTest(production=production, url=url), override_settings(EMAIL_PRODUCTION=production):
                    with self.assertRaises(ImproperlyConfigured) as error:
                        get_adapter().render_mail('account/email/password_reset_key', 'owner@recipient.test',
                                                  {'password_reset_url': url})
                    self.assertEqual(str(error.exception), 'Invalid application URL in supported account email.')

    @override_settings(ALLOWED_HOSTS=['app.test'])
    def test_rewrite_preserves_exact_suffix_and_ignores_other_variables(self):
        from unittest.mock import patch
        from allauth.account.adapter import DefaultAccountAdapter
        for production, canonical in ((False, ''), (False, 'http://canonical.test'), (True, 'https://canonical.test')):
            with self.subTest(production=production, canonical=canonical), override_settings(
                    EMAIL_PRODUCTION=production, APPLICATION_ORIGIN=canonical):
                for suffix in ('/reset/A%2Fb-TOKEN/?x=one%2Ftwo&x=three+four', '/reset/TOKEN/?'):
                    context = {'password_reset_url': 'http://app.test:8080' + suffix,
                               'signup_url': 'https://external.test/unchanged', 'activate_url': '//unchanged'}
                    with patch.object(DefaultAccountAdapter, 'render_mail') as parent:
                        get_adapter().render_mail('account/email/password_reset_key', 'owner@recipient.test', context)
                    passed = parent.call_args.args[2]
                    self.assertEqual(passed['password_reset_url'], (canonical or 'http://app.test:8080') + suffix)
                    self.assertEqual(passed['signup_url'], context['signup_url'])
                    self.assertEqual(passed['activate_url'], context['activate_url'])
                    self.assertEqual(context['password_reset_url'], 'http://app.test:8080' + suffix)

    @override_settings(EMAIL_PRODUCTION=True, APPLICATION_ORIGIN='https://canonical.test')
    def test_unsupported_template_is_untouched(self):
        from unittest.mock import patch
        from allauth.account.adapter import DefaultAccountAdapter
        context = {'password_reset_url': '//external.test/unmodified'}
        with patch.object(DefaultAccountAdapter, 'render_mail') as parent:
            get_adapter().render_mail('unrelated/email/message', 'owner@recipient.test', context)
        self.assertIs(parent.call_args.args[2], context)

    @override_settings(EMAIL_PRODUCTION=True, APPLICATION_ORIGIN='https://canonical.test', ALLOWED_HOSTS=[])
    def test_canonical_source_host_is_trusted_and_missing_url_fails(self):
        from unittest.mock import patch
        from allauth.account.adapter import DefaultAccountAdapter
        with patch.object(DefaultAccountAdapter, 'render_mail') as parent:
            get_adapter().render_mail('account/email/email_confirmation', 'owner@recipient.test',
                                      {'activate_url': 'https://canonical.test/confirm/TOKEN/'})
        self.assertEqual(parent.call_args.args[2]['activate_url'], 'https://canonical.test/confirm/TOKEN/')
        with self.assertRaises(ImproperlyConfigured):
            get_adapter().render_mail('account/email/email_confirmation', 'owner@recipient.test', {})
