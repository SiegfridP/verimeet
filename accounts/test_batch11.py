from django.test import TestCase
from django.urls import reverse
from accounts.models import User, Department, Membership
from meetings.models import Meeting, Attendance


class Batch11DashboardTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.dept = Department.objects.create(name='Engineering')
        cls.other = Department.objects.create(name='Other')
        cls.admin = User.objects.create_user(username='global', is_admin=True)
        cls.ap = User.objects.create_user(username='ap')
        cls.officer = User.objects.create_user(username='officer')
        cls.peer = User.objects.create_user(username='peer')
        Membership.objects.create(user=cls.admin, department=cls.dept, role='O')
        Membership.objects.create(user=cls.ap, department=cls.dept, role='AP')
        Membership.objects.create(user=cls.officer, department=cls.dept, role='O')
        cls.finished = Meeting.objects.create(department=cls.dept, title='Finished record', status='Finished')
        cls.unassigned = Meeting.objects.create(department=cls.dept, title='Unassigned record')
        cls.archived = Meeting.objects.create(department=cls.dept, title='Archived record', status='Archived')
        cls.secret = Meeting.objects.create(department=cls.other, title='OTHER SECRET')
        Attendance.objects.create(meeting=cls.finished, user=cls.officer, status='Late')
        Attendance.objects.create(meeting=cls.finished, user=cls.peer, has_signed=True,
                                  annotation='PRIVATE PEER ANNOTATION', cryptographic_signature='PRIVATE SIGNATURE')

    def dashboard(self, user, params=None, dept=None):
        self.client.force_login(user)
        return self.client.get(reverse('department_dashboard', args=[(dept or self.dept).pk]), params or {})

    def test_global_identity_and_navigation(self):
        response = self.dashboard(self.admin)
        self.assertContains(response, 'Global Admin — Department Dashboard')
        self.assertContains(response, reverse('admin_dashboard'))
        self.assertContains(response, 'Create Meeting')
        self.assertEqual(self.dashboard(self.admin, dept=self.other).status_code, 200)
        overview = self.client.get(reverse('admin_dashboard'), {'department': self.other.pk})
        self.assertContains(overview, 'OTHER SECRET')
        self.assertNotContains(overview, 'Finished record')
        self.assertContains(overview, reverse('department_dashboard', args=[self.dept.pk]))

    def test_isolation_and_no_membership_side_effect(self):
        before = Membership.objects.count()
        self.assertEqual(self.dashboard(self.ap, dept=self.other).status_code, 403)
        self.assertEqual(self.dashboard(self.officer, dept=self.other).status_code, 403)
        self.dashboard(self.admin, dept=self.other)
        self.assertEqual(Membership.objects.count(), before)

    def test_officer_department_wide_private_by_default(self):
        response = self.dashboard(self.officer)
        for title in ('Finished record', 'Unassigned record', 'Archived record', 'Not Assigned', 'Eligible to sign', 'Created'):
            self.assertContains(response, title)
        for secret in ('OTHER SECRET', 'PRIVATE PEER ANNOTATION', 'PRIVATE SIGNATURE', 'Export PDF', 'Document History', 'My Signature QR'):
            self.assertNotContains(response, secret)
        self.assertNotContains(response, reverse('my_attendance', args=[self.unassigned.pk]))

    def test_personal_filters_and_invalid_values(self):
        response = self.dashboard(self.officer, {'signing': 'signed'})
        self.assertNotContains(response, 'Finished record')
        response = self.dashboard(self.officer, {'attendance': 'Late'})
        self.assertContains(response, 'Finished record')
        self.assertNotContains(response, 'Unassigned record')
        response = self.dashboard(self.officer, {'assignment': 'invalid', 'status': 'invalid'})
        self.assertContains(response, 'Unassigned record')
        self.assertContains(self.dashboard(self.officer, {'assignment': 'unassigned'}), 'Unassigned record')

    def test_lifecycle_actions(self):
        response = self.dashboard(self.ap, {'status': 'Archived'})
        for name in ('review_meeting', 'document_history', 'export_meeting_pdf'):
            self.assertContains(response, reverse(name, args=[self.archived.pk]))
        for name in ('meeting_attendance', 'generate_attendance_qr', 'generate_signing_qr', 'lock_meeting'):
            self.assertNotContains(response, reverse(name, args=[self.archived.pk]))
        review = self.client.get(reverse('review_meeting', args=[self.archived.pk]))
        self.assertNotContains(review, 'Manage Attendance')
        self.assertNotContains(review, 'PDF Generated')

    def test_search_pagination_and_empty_states(self):
        Meeting.objects.bulk_create([Meeting(department=self.dept, title=f'Needle {i}') for i in range(23)])
        response = self.dashboard(self.ap, {'q': 'Needle', 'status': 'Draft'})
        self.assertEqual(len(response.context['meetings']), 20)
        self.assertContains(response, 'q=Needle&amp;status=Draft&amp;page=2')
        second = self.dashboard(self.ap, {'q': 'Needle', 'status': 'Draft', 'page': 2})
        self.assertEqual(len(second.context['meetings']), 3)
        self.assertContains(self.dashboard(self.ap, {'q': 'nothing matches'}), 'No meetings match')

    def test_officer_management_denials(self):
        self.dashboard(self.officer)
        for name in ('review_meeting', 'document_history', 'export_meeting_pdf', 'meeting_attendance', 'assign_participants'):
            self.assertEqual(self.client.get(reverse(name, args=[self.finished.pk])).status_code, 403)

    def test_noop_feedback(self):
        self.dashboard(self.ap)
        response = self.client.post(reverse('edit_meeting', args=[self.unassigned.pk]),
                                    {'title': self.unassigned.title, 'minutes_content': ''}, follow=True)
        self.assertContains(response, 'No changes to save.')
        self.assertContains(response, 'class="message info"')

    def test_signed_qr_is_personal(self):
        Attendance.objects.filter(meeting=self.finished, user=self.officer).update(
            has_signed=True, cryptographic_signature='not-rendered')
        response = self.dashboard(self.officer)
        self.assertContains(response, reverse('my_signature_verification_qr', args=[self.finished.pk]))
        self.assertContains(response, 'Signed')
        self.assertNotContains(response, 'not-rendered')
        self.assertNotContains(response, 'PRIVATE SIGNATURE')

    def test_switcher_includes_memberships_with_department_scoped_roles(self):
        Membership.objects.create(user=self.ap, department=self.other, role='O')
        response = self.dashboard(self.ap)
        self.assertContains(response, reverse('department_dashboard', args=[self.other.pk]))
        officer_context = self.dashboard(self.ap, dept=self.other)
        self.assertTemplateUsed(officer_context, 'accounts/member_dashboard.html')
        self.assertNotContains(officer_context, 'Create Meeting')
        self.assertContains(officer_context, reverse('department_dashboard', args=[self.dept.pk]))
        Membership.objects.filter(user=self.ap, department=self.other).update(role='AP')
        self.assertContains(self.dashboard(self.ap, {'q': 'record'}),
                            reverse('department_dashboard', args=[self.other.pk]) + '?q=record')

    def test_officer_switcher_excludes_inactive_and_unjoined_departments(self):
        Membership.objects.create(user=self.officer, department=self.other, role='O')
        inactive = Department.objects.create(name='Inactive', is_active=False)
        Membership.objects.create(user=self.officer, department=inactive, role='AP')
        unjoined = Department.objects.create(name='Unjoined')
        for department in (self.dept, self.other):
            response = self.dashboard(self.officer, {'q': 'record'}, dept=department)
            self.assertTemplateUsed(response, 'accounts/member_dashboard.html')
            for target in (self.dept, self.other):
                self.assertContains(response, reverse('department_dashboard', args=[target.pk]) + '?q=record')
            for target in (inactive, unjoined):
                self.assertNotContains(response, reverse('department_dashboard', args=[target.pk]))
            self.assertNotContains(response, 'Create Meeting')
        self.assertEqual(self.dashboard(self.officer, dept=inactive).status_code, 404)

    def test_active_routing_is_deterministic_and_precedes_legacy(self):
        # First-created membership is inactive; active selection uses department PK.
        inactive = Department.objects.create(name='Inactive', is_active=False)
        user = User.objects.create_user(username='multi-routing', department=inactive)
        Membership.objects.create(user=user, department=self.other, role='O')
        Membership.objects.create(user=user, department=self.dept, role='AP')
        self.client.force_login(user)
        self.assertRedirects(self.client.get(reverse('routing_view')),
                             reverse('department_dashboard', args=[self.dept.pk]))
        User.objects.filter(pk=user.pk).update(department=self.other)
        self.assertRedirects(self.client.get(reverse('routing_view')),
                             reverse('department_dashboard', args=[self.dept.pk]))

    def test_inactive_only_memberships_and_legacy_stay_in_waiting_room(self):
        Department.objects.filter(pk=self.dept.pk).update(is_active=False)
        legacy = User.objects.create_user(username='inactive-legacy', department=self.dept)
        Membership.objects.filter(user=legacy).delete()
        for user in (self.officer, legacy):
            self.client.force_login(user)
            if user == legacy:
                Membership.objects.filter(user=legacy).delete()
            self.assertRedirects(self.client.get(reverse('routing_view')), reverse('waiting_room'))
            self.assertContains(self.client.get(reverse('waiting_room')), 'Waiting Room')

    def test_active_legacy_fallback_remains_officer_without_membership_creation(self):
        user = User.objects.create_user(username='active-legacy', department=self.dept)
        self.client.force_login(user)
        Membership.objects.filter(user=user).delete()
        self.assertRedirects(self.client.get(reverse('routing_view')),
                             reverse('department_dashboard', args=[self.dept.pk]))
        response = self.client.get(reverse('department_dashboard', args=[self.dept.pk]))
        self.assertTemplateUsed(response, 'accounts/member_dashboard.html')
        self.assertNotContains(response, 'Create Meeting')
        self.assertFalse(Membership.objects.filter(user=user).exists())

    def test_memberships_block_unrelated_active_legacy_access(self):
        # Set the stale pointer after login so the user-save compatibility signal
        # does not create a membership for the legacy department.
        self.client.force_login(self.officer)
        User.objects.filter(pk=self.officer.pk).update(department=self.other)
        legacy_url = reverse('department_dashboard', args=[self.other.pk])
        self.assertRedirects(self.client.get(reverse('routing_view')),
                             reverse('department_dashboard', args=[self.dept.pk]))
        self.assertEqual(self.client.get(legacy_url).status_code, 403)
        Department.objects.filter(pk=self.dept.pk).update(is_active=False)
        self.assertRedirects(self.client.get(reverse('routing_view')), reverse('waiting_room'))
        self.assertContains(self.client.get(reverse('waiting_room')), 'Waiting Room')
        self.assertEqual(self.client.get(legacy_url).status_code, 403)
        self.assertFalse(Membership.objects.filter(user=self.officer, department=self.other).exists())

    def test_global_precedence_and_staff_distinction_with_inactive_memberships(self):
        Department.objects.filter(pk=self.dept.pk).update(is_active=False)
        superuser = User.objects.create_user(username='super-routing', is_superuser=True)
        staff = User.objects.create_user(username='staff-routing', is_staff=True)
        Membership.objects.create(user=staff, department=self.dept, role='AP')
        for user in (self.admin, superuser):
            self.client.force_login(user)
            self.assertRedirects(self.client.get(reverse('routing_view')), reverse('admin_dashboard'))
            response = self.client.get(reverse('waiting_room'), follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.redirect_chain[-1][0], reverse('admin_dashboard'))
            self.assertEqual(self.client.get(reverse('department_dashboard', args=[self.other.pk])).status_code, 200)
        self.client.force_login(staff)
        self.assertRedirects(self.client.get(reverse('routing_view')), reverse('waiting_room'))
        self.assertEqual(self.client.get(reverse('admin_dashboard')).status_code, 403)

    def test_legacy_dashboard_does_not_create_membership(self):
        legacy = User.objects.create_user(username='legacy', department=self.dept)
        self.client.force_login(legacy)
        Membership.objects.filter(user=legacy).delete()
        self.assertEqual(self.client.get(reverse('department_dashboard', args=[self.dept.pk])).status_code, 200)
        self.assertFalse(Membership.objects.filter(user=legacy).exists())

    def test_message_severity_all_dashboards(self):
        from django.contrib.messages import constants
        from django.contrib.messages.storage.cookie import CookieStorage
        from django.contrib.messages.storage.base import Message
        for user, url in ((self.admin, reverse('admin_dashboard')),
                          (self.ap, reverse('department_dashboard', args=[self.dept.pk])),
                          (self.officer, reverse('department_dashboard', args=[self.dept.pk]))):
            for level, tag in ((constants.SUCCESS, 'success'), (constants.INFO, 'info'),
                               (constants.WARNING, 'warning'), (constants.ERROR, 'error')):
                self.client.force_login(user)
                self.client.cookies['messages'] = CookieStorage(None)._encode([Message(level, 'Feedback')])
                self.assertContains(self.client.get(url), f'class="message {tag}"')
