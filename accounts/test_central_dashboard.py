from django.test import TestCase
from django.urls import reverse
from .models import Department, Membership, User


class CentralDashboardTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='central-user')
        self.a = Department.objects.create(name='Alpha')
        self.b = Department.objects.create(name='Beta')
        self.inactive = Department.objects.create(name='Inactive', is_active=False)
        self.other = Department.objects.create(name='Unjoined')
        self.url = reverse('central_dashboard')

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
