from pathlib import Path
from django.test import TestCase
from django.template.loader import get_template
from django.contrib.staticfiles import finders
from django.urls import reverse


class ApplicationPresentationTests(TestCase):
    def test_project_templates_compile_and_stylesheet_is_discoverable(self):
        root = Path(__file__).resolve().parent.parent
        count = 0
        for directory in (root / 'accounts/templates', root / 'meetings/templates'):
            for path in directory.rglob('*.html'):
                with self.subTest(template=str(path)):
                    get_template(path.relative_to(directory).as_posix())
                    count += 1
        self.assertGreaterEqual(count, 47)
        self.assertTrue(finders.find('css/verimeet.css'))

    def test_authentication_shell_and_forms_render(self):
        for route in ('account_login', 'account_signup', 'account_reset_password'):
            with self.subTest(route=route):
                response = self.client.get(reverse(route))
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, 'css/verimeet.css')
                self.assertContains(response, 'Skip to content')
                self.assertContains(response, 'csrfmiddlewaretoken')
                self.assertContains(response, 'method="post"')
                self.assertNotContains(response, 'fonts.googleapis.com')

    def test_standard_error_templates_render_without_request_context(self):
        for code in ('403', '404', '500'):
            html = get_template(code + '.html').render({})
            self.assertIn('css/verimeet.css', html)
            self.assertIn('main-content', html)

    def test_authenticated_logout_keeps_confirmation_post(self):
        from .models import User
        user = User.objects.create_user(username='ui-logout')
        self.client.force_login(user)
        response = self.client.get(reverse('account_logout'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'css/verimeet.css')
        self.assertContains(response, 'csrfmiddlewaretoken')
        self.assertContains(response, 'method="post"')

    def test_notifications_render_once_in_shared_region(self):
        from django.contrib.auth.models import AnonymousUser
        from django.contrib.messages.storage.fallback import FallbackStorage
        from django.contrib import messages
        from django.test import RequestFactory
        for template in ('base_app.html', 'allauth/layouts/base.html',
                         'accounts/account_settings.html', 'accounts/central_dashboard.html',
                         'accounts/waiting_room.html', 'accounts/onboarding.html'):
            with self.subTest(template=template):
                request = RequestFactory().get('/')
                request.user = AnonymousUser()
                request.session = {}
                request._messages = FallbackStorage(request)
                messages.success(request, 'Unique success notice')
                messages.warning(request, 'Unique warning notice')
                html = get_template(template).render({}, request)
                self.assertEqual(html.count('aria-label="Notifications" role="status"'), 1)
                self.assertEqual(html.count('Unique success notice'), 1)
                self.assertEqual(html.count('Unique warning notice'), 1)
                self.assertIn('class="message success"', html)
                self.assertIn('class="message warning"', html)
                self.assertIn('VeriMeet | Meeting management', html)
                self.assertNotIn('VeriMeet ? Meeting', html)

    def test_get_logout_does_not_end_session(self):
        from .models import User
        user = User.objects.create_user(username='ui-confirm-logout')
        self.client.force_login(user)
        response = self.client.get(reverse('account_logout'))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.wsgi_request.user.is_authenticated)
        self.assertIn('_auth_user_id', self.client.session)
        self.client.post(reverse('account_logout'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_workspace_navigation_active_state_and_public_variants(self):
        from types import SimpleNamespace
        from django.test import RequestFactory
        from .models import User
        user = User.objects.create_user(username='workspace-navigation')
        request = RequestFactory().get(reverse('account_settings'))
        request.user = user
        request.session = {}
        request.resolver_match = SimpleNamespace(url_name='account_settings')
        html = get_template('base_app.html').render({}, request)
        self.assertIn('id="workspace-navigation"', html)
        self.assertIn('aria-controls="workspace-navigation"', html)
        self.assertIn('aria-expanded="true"', html)
        self.assertIn('href="' + reverse('account_settings') + '" aria-current="page"', html)
        self.assertNotIn('Manage accounts', html)
        for name in ('allauth/layouts/base.html', '403.html', '404.html', '500.html',
                     'meetings/individual_signature_verification.html', 'meetings/qr_projector.html'):
            with self.subTest(template=name):
                department = SimpleNamespace(id=1, pk=1, name='Public display')
                context = {'status': 'invalid', 'meeting': None}
                if name.endswith('qr_projector.html'):
                    context = {'meeting': SimpleNamespace(id=1, title='Projector', department=department),
                               'qr_session': True, 'qr_image_b64': 'preview', 'signing_url': '/sign/'}
                html = get_template(name).render(context, request)
                self.assertNotIn('id="workspace-navigation"', html)
                self.assertNotIn('aria-label="Account"', html)
                if name.endswith('qr_projector.html'):
                    self.assertIn('width="280"', html)
                    self.assertIn('height="280"', html)
                    self.assertIn('id="signing-link"', html)

    def test_signing_fields_and_annotation_handler_remain_in_workspace(self):
        from types import SimpleNamespace
        from django.test import RequestFactory
        from .models import User
        request = RequestFactory().get('/')
        request.user = User(username='signer')
        request.session = {}
        department = SimpleNamespace(id=1, pk=1, name='Department')
        html = get_template('meetings/sign_document.html').render({
            'meeting': SimpleNamespace(id=1, title='Final document', department=department, minutes_content='Minutes'),
            'attendance': SimpleNamespace(status='Attended'),
            'qr_token': 'test-token', 'timestamp': '123', 'sig': 'test-signature',
        }, request)
        for fragment in ('name="token" value="test-token"', 'name="t" value="123"',
                         'name="sig" value="test-signature"', 'name="annotation"',
                         'id="char-counter"', 'id="btn-sign-submit"', 'oninput=',
                         'csrfmiddlewaretoken', 'method="post"'):
            self.assertIn(fragment, html)
