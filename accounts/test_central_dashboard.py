from django.test import TestCase
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from tempfile import TemporaryDirectory
from .models import Department, Membership, User
from .test_onboarding import png


class CentralDashboardTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        override = override_settings(PRIVATE_SIGNATURE_ROOT=directory.name)
        override.enable()
        self.addCleanup(override.disable)
        self.user = User.objects.create_user(username='central-user')
        self.complete_onboarding(self.user)
        self.a = Department.objects.create(name='Alpha')
        self.b = Department.objects.create(name='Beta')
        self.inactive = Department.objects.create(name='Inactive', is_active=False)
        self.other = Department.objects.create(name='Unjoined')
        self.url = reverse('central_dashboard')

    def complete_onboarding(self, user):
        user.signature_image.save('signature.png', SimpleUploadedFile('signature.png', png()))

    def test_anonymous_and_default_routing(self):
        self.assertRedirects(self.client.get(self.url), reverse('account_login') + '?next=' + self.url)
        self.client.force_login(self.user)
        self.assertRedirects(self.client.get(reverse('routing_view')), self.url)
        self.assertContains(self.client.get(self.url), 'You have no active departments')

    def test_memberships_roles_navigation_and_no_mutations(self):
        Membership.objects.create(user=self.user, department=self.a, role='AP')
        Membership.objects.create(user=self.user, department=self.b, role='O')
        Membership.objects.create(user=self.user, department=self.inactive)
        self.client.force_login(self.user)
        before = list(Membership.objects.values())
        response = self.client.get(self.url)
        entries = response.context['department_entries']
        self.assertEqual([(e['department'].pk, e['role']) for e in entries],
                         [(self.a.pk, 'Authorized Personnel'), (self.b.pk, 'Officer')])
        self.assertNotContains(response, 'Unjoined')
        self.assertNotContains(response, 'Inactive')
        self.assertEqual(before, list(Membership.objects.values()))
        for department in (self.a, self.b):
            self.assertRedirects(self.client.get(reverse('routing_view')), self.url)
            page = self.client.get(reverse('department_dashboard', args=[department.pk]))
            self.assertContains(page, 'href="' + self.url + '"')
            self.assertContains(page, 'Switch department')
            self.assertNotContains(page, 'Create Department')
        self.assertEqual(self.client.get(reverse('department_dashboard', args=[self.other.pk])).status_code, 404)

    def test_legacy_access_is_officer_and_real_memberships_override(self):
        self.user.department = self.a
        self.user.save()
        self.client.force_login(self.user)
        entries = self.client.get(self.url).context['department_entries']
        self.assertEqual([(e['department'].pk, e['role']) for e in entries], [(self.a.pk, 'Officer')])
        self.assertFalse(Membership.objects.filter(user=self.user).exists())
        self.assertEqual(self.client.get(reverse('invite_member', args=[self.a.pk])).status_code, 404)
        Department.objects.filter(pk=self.a.pk).update(is_active=False)
        self.assertEqual(self.client.get(self.url).context['department_entries'], [])
        Department.objects.filter(pk=self.a.pk).update(is_active=True)
        Membership.objects.create(user=self.user, department=self.inactive)
        self.assertEqual(self.client.get(self.url).context['department_entries'], [])
        self.assertEqual(self.client.get(reverse('department_dashboard', args=[self.a.pk])).status_code, 404)

    def test_admin_staff_and_compatibility(self):
        for flags in ({'is_admin': True}, {'is_superuser': True}, {'is_staff': True}):
            user = User.objects.create_user(username=next(iter(flags)), **flags)
            if not (user.is_admin or user.is_superuser):
                self.complete_onboarding(user)
            self.client.force_login(user)
            admin = not flags.get('is_staff')
            destination = reverse('admin_dashboard') if admin else self.url
            self.assertRedirects(self.client.get(reverse('routing_view')), destination)
            response = self.client.get(reverse('waiting_room'), follow=True)
            self.assertEqual(response.redirect_chain, [(destination, 302)])
            if admin:
                self.assertRedirects(self.client.get(self.url), destination)
                self.assertContains(response, 'Create Department')
                page = self.client.get(reverse('department_dashboard', args=[self.a.pk]))
                self.assertContains(page, 'Global Admin Dashboard')
                self.assertNotContains(page, 'Back to My Dashboard')

    def test_officer_compatibility_selects_active_memberships_deterministically(self):
        from .views import active_department_for_user
        Membership.objects.create(user=self.user, department=self.inactive)
        # Reverse insertion order: selection follows department ID, not row ID.
        Membership.objects.create(user=self.user, department=self.b, role='AP')
        Membership.objects.create(user=self.user, department=self.a, role='O')
        self.client.force_login(self.user)
        self.assertEqual(active_department_for_user(self.user), self.a)
        for route in ('officer_dashboard', 'student_dashboard'):
            self.assertRedirects(self.client.get(reverse(route)),
                                 reverse('department_dashboard', args=[self.a.pk]))
        Department.objects.filter(pk=self.a.pk).update(is_active=False)
        response = self.client.get(reverse('officer_dashboard'), follow=True)
        self.assertTemplateUsed(response, 'accounts/authorized_dashboard.html')
        self.assertEqual(response.context['department'], self.b)
        self.assertTrue(response.context['can_manage'])

    def test_officer_compatibility_inactive_only_suppresses_legacy_fallback(self):
        self.user.department = self.a
        self.user.save(update_fields=['department'])
        Membership.objects.create(user=self.user, department=self.inactive)
        self.client.force_login(self.user)
        response = self.client.get(reverse('officer_dashboard'), follow=True)
        self.assertEqual(response.redirect_chain, [(reverse('waiting_room'), 302), (self.url, 302)])
        self.assertEqual(response.context['department_entries'], [])
        self.assertEqual(self.client.get(reverse('department_dashboard', args=[self.a.pk])).status_code, 404)

    def test_officer_compatibility_legacy_and_explicit_scope(self):
        self.client.force_login(self.user)
        self.assertRedirects(self.client.get(reverse('officer_dashboard')), reverse('waiting_room'),
                             fetch_redirect_response=False)
        self.user.department = self.a
        self.user.save(update_fields=['department'])
        self.assertRedirects(self.client.get(reverse('officer_dashboard')),
                             reverse('department_dashboard', args=[self.a.pk]))
        self.assertTemplateUsed(self.client.get(reverse('department_dashboard', args=[self.a.pk])),
                                'accounts/member_dashboard.html')
        Department.objects.filter(pk=self.a.pk).update(is_active=False)
        self.assertRedirects(self.client.get(reverse('officer_dashboard')), reverse('waiting_room'),
                             fetch_redirect_response=False)
        Department.objects.filter(pk=self.a.pk).update(is_active=True)
        Membership.objects.create(user=self.user, department=self.b, role='O')
        self.assertRedirects(self.client.get(reverse('officer_dashboard')),
                             reverse('department_dashboard', args=[self.b.pk]))
        for department in (self.a, self.inactive, self.other):
            self.assertEqual(self.client.get(reverse('officer_dashboard'),
                                            {'dept_id': department.pk}).status_code, 403)

    def test_officer_compatibility_global_admin_precedence(self):
        for flags in ({'is_admin': True}, {'is_superuser': True}):
            user = User.objects.create_user(username='compat-' + next(iter(flags)), **flags)
            Membership.objects.create(user=user, department=self.inactive)
            Membership.objects.create(user=user, department=self.a, role='O')
            self.client.force_login(user)
            self.assertRedirects(self.client.get(reverse('officer_dashboard')), reverse('admin_dashboard'))
            # An explicit authorized department context still takes precedence.
            self.assertRedirects(self.client.get(reverse('officer_dashboard'), {'dept_id': self.b.pk}),
                                 reverse('department_dashboard', args=[self.b.pk]))
