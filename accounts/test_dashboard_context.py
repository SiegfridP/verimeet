import json
from html import unescape
import re
from urllib.parse import parse_qs, urlsplit
from django.test import TestCase, RequestFactory
from django.test import override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from tempfile import TemporaryDirectory
from django.urls import reverse, resolve
from accounts.models import User, Department, Membership
from accounts.dashboard_context import context, destination, workflow_url
from meetings.models import Meeting, Attendance


class DashboardContextTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        storage = override_settings(PRIVATE_SIGNATURE_ROOT=directory.name)
        storage.enable()
        self.addCleanup(storage.disable)
        from accounts.test_onboarding import png
        # Exercise navigation with completed onboarding, without bypassing it.
        for user in (self.ap, self.officer):
            user.signature_image.save('signature.png', SimpleUploadedFile('signature.png', png()))

    @classmethod
    def setUpTestData(cls):
        cls.dept = Department.objects.create(name='Context department')
        cls.other = Department.objects.create(name='Other context department')
        cls.ap = User.objects.create_user(username='context-ap')
        cls.officer = User.objects.create_user(username='context-officer')
        cls.admin = User.objects.create_user(username='context-admin', is_admin=True)
        Membership.objects.create(user=cls.ap, department=cls.dept, role='AP')
        Membership.objects.create(user=cls.officer, department=cls.dept, role='O')
        cls.meeting = Meeting.objects.create(department=cls.dept, title='Context meeting')
        Attendance.objects.create(meeting=cls.meeting, user=cls.officer)

    def data(self, kind='department'):
        return {'kind': kind, 'dept': self.dept.pk, 'q': ' Context ', 'status': 'Draft', 'page': '2'}

    def request(self, data, user=None):
        request = RequestFactory().get('/workflow/', {'dashboard_context': json.dumps(data)})
        request.user = user or self.ap
        request.resolver_match = None
        return request

    def test_back_cancel_and_intermediate_pages(self):
        for user, names in ((self.ap, ('review_meeting', 'edit_meeting', 'assign_participants', 'meeting_attendance', 'document_history', 'projector_qr_view')),
                            (self.officer, ('my_attendance',))):
            self.client.force_login(user)
            for name in names:
                with self.subTest(user=user.username, name=name):
                    if name == 'projector_qr_view':
                        Meeting.objects.filter(pk=self.meeting.pk).update(status='Finished')
                    response = self.client.get(reverse(name, args=[self.meeting.pk]), {'dashboard_context': json.dumps(self.data())})
                    self.assertEqual(response.status_code, 200)
                    self.assertContains(response, reverse('department_dashboard', args=[self.dept.pk]) + '?q=Context&amp;status=Draft&amp;page=2')
                    if name in ('review_meeting', 'edit_meeting', 'assign_participants', 'meeting_attendance'):
                        self.assertContains(response, 'name="dashboard_context"')

    def test_global_origins_and_direct_fallback(self):
        self.client.force_login(self.admin)
        for kind in ('overview', 'department'):
            response = self.client.get(reverse('review_meeting', args=[self.meeting.pk]), {'dashboard_context': json.dumps(self.data(kind))})
            target = 'admin_dashboard' if kind == 'overview' else 'department_dashboard'
            expected = reverse(target, args=[] if kind == 'overview' else [self.dept.pk])
            self.assertContains(response, expected + '?q=Context&amp;status=Draft&amp;page=2')
        response = self.client.get(reverse('review_meeting', args=[self.meeting.pk]))
        self.assertContains(response, reverse('department_dashboard', args=[self.dept.pk]))

    def test_mutation_returns_reset_page(self):
        for user, kind in ((self.ap, 'department'), (self.admin, 'overview')):
            self.client.force_login(user)
            for name, fields in (('edit_meeting', {'title': 'Changed context', 'minutes_content': ''}),
                                 ('assign_participants', {'participants': [self.officer.pk]}),
                                 ('finalize_meeting', {})):
                Meeting.objects.filter(pk=self.meeting.pk).update(status='Draft')
                with self.subTest(user=user.username, name=name):
                    response = self.client.post(reverse(name, args=[self.meeting.pk]), {**fields, 'dashboard_context': json.dumps(self.data(kind))})
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response.url, destination(context(self.request(self.data(kind), user)), reset=True))

    def test_validation_and_sensitive_keys(self):
        invalid = [{'kind': 'external'}, {'kind': 'overview'}, {'kind': 'department', 'dept': 'bad'}, {'kind': 'department', 'dept': self.other.pk}]
        for data in invalid:
            with self.subTest(data=data):
                self.assertIsNone(context(self.request(data)))
        data = self.data()
        data.update(next='https://evil.invalid', token='secret', sig='secret', action='approve', attendance='invalid')
        normalized = context(self.request(data))
        self.assertEqual(normalized, {'kind': 'department', 'dept': self.dept.pk, 'q': 'Context', 'status': 'Draft', 'page': '2'})
        for value in ('bad', '-1', '0', '999999999999999999999', 'https://evil.invalid'):
            self.assertNotIn('page', context(self.request({**data, 'page': value})))
        self.dept.is_active = False
        self.dept.save()
        self.assertIsNone(context(self.request(data)))

    def test_dashboard_generated_links_and_filter_reset(self):
        Membership.objects.create(user=self.ap, department=self.other, role='O')
        self.client.force_login(self.ap)
        url = reverse('department_dashboard', args=[self.dept.pk])
        response = self.client.get(url, {'q': 'Context', 'page': 2, 'token': 'secret'})
        html = response.content.decode()
        link = next(unescape(v) for v in re.findall('href="([^"]+)"', html) if '/review/' in v)
        payload = json.loads(parse_qs(urlsplit(link).query)['dashboard_context'][0])
        self.assertNotIn('token', payload)
        self.assertEqual(payload['page'], '2')
        form = re.search('<form method="get">(.*?)</form>', html, re.S).group(1)
        self.assertNotIn('name="page"', form)
        self.assertNotIn('&quot;page&quot;', form)
        self.assertContains(response, reverse('department_dashboard', args=[self.other.pk]) + '?q=Context')
        response = self.client.get(url, {'q': 'Context'})
        self.assertEqual(response.context['page_obj'].number, 1)

    def test_officer_mutation_context_and_authorization(self):
        data = {**self.data(), 'assignment': 'assigned', 'attendance': 'Late', 'signing': 'eligible'}
        request = self.request(data, self.officer)
        normalized = context(request)
        target = workflow_url(request, 'department_dashboard', kwargs={'dept_id': self.dept.pk}, reset=True)
        self.assertNotIn('page=', target)
        self.assertIn('assignment=assigned', target)
        self.client.force_login(self.officer)
        response = self.client.post(reverse('edit_meeting', args=[self.meeting.pk]), {'dashboard_context': json.dumps(data)})
        self.assertEqual(response.status_code, 403)
        self.assertIsNotNone(normalized)


    def test_attendance_and_qr_intermediate_mutations(self):
        self.client.force_login(self.ap)
        attendance = Attendance.objects.get(meeting=self.meeting, user=self.officer)
        response = self.client.post(reverse('update_attendance_status', args=[self.meeting.pk, attendance.pk]),
            {'status': 'Late', 'dashboard_context': json.dumps(self.data())})
        self.assertEqual(response.status_code, 302)
        payload = json.loads(parse_qs(urlsplit(response.url).query)['dashboard_context'][0])
        self.assertNotIn('page', payload)
        self.assertEqual(payload['q'], 'Context')
        self.assertContains(self.client.get(response.url), reverse('department_dashboard', args=[self.dept.pk]) + '?q=Context&amp;status=Draft')
        response = self.client.post(reverse('generate_attendance_qr', args=[self.meeting.pk]),
            {'dashboard_context': json.dumps(self.data())})
        self.assertEqual(response.status_code, 302)
        self.assertContains(self.client.get(response.url), 'dashboard_context')

    def test_officer_signing_success_resets_page(self):
        import time
        from meetings.crypto import generate_hmac_qr_token
        Meeting.objects.filter(pk=self.meeting.pk).update(status='Finished', minutes_content='Final notes')
        Attendance.objects.filter(meeting=self.meeting, user=self.officer).update(status='Late')
        self.client.force_login(self.officer)
        timestamp = str(int(time.time()))
        response = self.client.post(reverse('sign_meeting', args=[self.meeting.pk]),
            {'t': timestamp, 'sig': generate_hmac_qr_token(self.meeting.pk, timestamp),
             'annotation': 'Confirmed', 'dashboard_context': json.dumps(self.data())})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('department_dashboard', args=[self.dept.pk]) + '?q=Context&status=Draft')

    def links(self, response):
        return [unescape(v) for v in re.findall('href="([^"]+)"', response.content.decode())]

    def overview_department_page(self):
        self.client.force_login(self.admin)
        overview = self.client.get(reverse('admin_dashboard'), {'q': 'Context', 'status': 'Draft', 'department': self.dept.pk})
        entry = next(link for link in self.links(overview) if urlsplit(link).path == reverse('department_dashboard', args=[self.dept.pk]))
        return self.client.get(entry)

    def test_rendered_overview_department_workflow_roundtrip(self):
        department = self.overview_department_page()
        expected = reverse('admin_dashboard') + '?department=' + str(self.dept.pk) + '&q=Context&status=Draft'
        for name in ('review_meeting', 'edit_meeting', 'document_history', 'meeting_attendance'):
            link = next(link for link in self.links(department) if urlsplit(link).path == reverse(name, args=[self.meeting.pk])) if name != 'meeting_attendance' else None
            if link:
                response = self.client.get(link)
                self.assertIn(expected, self.links(response))
        direct = self.client.get(reverse('department_dashboard', args=[self.dept.pk]))
        link = next(link for link in self.links(direct) if '/review/' in link)
        self.assertEqual(json.loads(parse_qs(urlsplit(link).query)['dashboard_context'][0])['kind'], 'department')

    def test_rendered_switch_filter_pagination_and_mutation_origin(self):
        other_meeting = Meeting.objects.create(department=self.other, title='Context other')
        department = self.overview_department_page()
        switch = next(link for link in self.links(department) if urlsplit(link).path == reverse('department_dashboard', args=[self.other.pk]))
        switched = self.client.get(switch)
        review = next(link for link in self.links(switched) if '/review/' in link)
        self.assertEqual(json.loads(parse_qs(urlsplit(review).query)['dashboard_context'][0])['kind'], 'overview')
        form = re.search('<form method="get">(.*?)</form>', switched.content.decode(), re.S).group(1)
        hidden = unescape(re.search('name="dashboard_context" value="([^"]+)"', form).group(1))
        filtered = self.client.get(urlsplit(switch).path, {'q': 'Context', 'status': 'Draft', 'dashboard_context': hidden})
        review = next(link for link in self.links(filtered) if '/review/' in link)
        page = self.client.get(review)
        self.assertIn(reverse('admin_dashboard') + '?department=' + str(self.dept.pk) + '&q=Context&status=Draft', self.links(page))
        edit = next(link for link in self.links(page) if '/edit/' in link)
        edit_page = self.client.get(edit)
        hidden = unescape(re.search('name="dashboard_context" value="([^"]+)"', edit_page.content.decode()).group(1))
        result = self.client.post(edit, {'title': 'Context changed', 'minutes_content': '', 'dashboard_context': hidden})
        self.assertEqual(urlsplit(result.url).path, reverse('admin_dashboard'))
        self.assertNotIn('page', parse_qs(urlsplit(result.url).query))
        from meetings.models import AuditLog
        AuditLog.objects.bulk_create([AuditLog(meeting=other_meeting, department=self.other, action='Event') for _ in range(26)])
        history = next(link for link in self.links(filtered) if '/history/' in link)
        history_page = self.client.get(history)
        next_page = next(link for link in self.links(history_page) if link.startswith('?page=2'))
        self.assertIn('dashboard_context=', next_page)
        self.assertIn(reverse('admin_dashboard') + '?department=' + str(self.dept.pk) + '&q=Context&status=Draft', self.links(self.client.get(urlsplit(history).path + next_page)))

    def test_overview_department_filter_policy_matches_context(self):
        inactive = Department.objects.create(name='Inactive context', is_active=False)
        inactive_meeting = Meeting.objects.create(department=inactive, title='Inactive meeting')
        self.client.force_login(self.admin)
        cases = [(str(self.dept.pk), str(self.dept.pk), [self.meeting.pk]),
                 (str(inactive.pk), str(inactive.pk), [inactive_meeting.pk]),
                 ('000' + str(self.dept.pk), str(self.dept.pk), [self.meeting.pk])]
        cases += [(value, '0', []) for value in ('999999999', '0', 'bad', '999999999999999999999')]
        for value, canonical, meetings in cases:
            with self.subTest(value=value):
                response = self.client.get(reverse('admin_dashboard'), {'department': value})
                self.assertEqual([m.pk for m in response.context['meetings']], meetings)
                self.assertEqual(response.context['department_filter'], canonical)
                entry = next(link for link in self.links(response) if urlsplit(link).path == reverse('department_dashboard', args=[self.dept.pk]))
                payload = json.loads(parse_qs(urlsplit(entry).query)['dashboard_context'][0])
                self.assertEqual(payload['department'], canonical)
                self.assertEqual(context(self.request(payload, self.admin))['department'], canonical)

    def test_overview_ancillary_rendered_navigation(self):
        self.client.force_login(self.admin)
        overview = self.client.get(reverse('admin_dashboard'), {'q': 'Context'})
        elevation = next(link for link in self.links(overview) if '/elevation-requests/' in link)
        self.assertIn(reverse('admin_dashboard') + '?q=Context', self.links(self.client.get(elevation)))
        payload = parse_qs(urlsplit(elevation).query)['dashboard_context'][0]
        selection = self.client.get(reverse('create_meeting'), {'dashboard_context': payload})
        self.assertIn(reverse('admin_dashboard') + '?q=Context', self.links(selection))

    def test_context_revalidated_after_access_changes(self):
        data = self.data()
        Membership.objects.filter(user=self.ap).delete()
        self.assertIsNone(context(self.request(data)))
        self.dept.is_active = False
        self.dept.save()
        self.assertIsNone(context(self.request(data, self.admin)))
        self.client.force_login(self.officer)
        response = self.client.get(reverse('department_dashboard', args=[self.dept.pk]), {'dashboard_context': json.dumps({'kind': 'overview'})})
        self.assertEqual(response.status_code, 404)

    def test_overview_origin_dashboard_pagination(self):
        Meeting.objects.bulk_create([Meeting(department=self.dept, title='Context page') for _ in range(22)])
        department = self.overview_department_page()
        next_link = next(link for link in self.links(department) if link.startswith('?') and 'page=2' in link)
        page_two = self.client.get(reverse('department_dashboard', args=[self.dept.pk]) + next_link)
        self.assertEqual(page_two.context['page_obj'].number, 2)
        workflow = next(link for link in self.links(page_two) if '/review/' in link)
        self.assertEqual(json.loads(parse_qs(urlsplit(workflow).query)['dashboard_context'][0])['kind'], 'overview')
        form = re.search('<form method="get">(.*?)</form>', page_two.content.decode(), re.S).group(1)
        hidden = unescape(re.search('name="dashboard_context" value="([^"]+)"', form).group(1))
        self.assertNotIn('page', json.loads(hidden))
        first = self.client.get(reverse('department_dashboard', args=[self.dept.pk]), {'q': 'Context', 'status': 'Draft', 'dashboard_context': hidden})
        self.assertEqual(first.context['page_obj'].number, 1)

    def test_forged_overview_on_authorized_department(self):
        self.client.force_login(self.officer)
        response = self.client.get(reverse('department_dashboard', args=[self.dept.pk]), {'dashboard_context': json.dumps({'kind': 'overview'})})
        link = next(link for link in self.links(response) if '/my-attendance/' in link)
        self.assertEqual(json.loads(parse_qs(urlsplit(link).query)['dashboard_context'][0])['kind'], 'department')

    def test_overview_filters_applied_and_synchronized(self):
        Meeting.objects.create(department=self.dept, title='Unrelated', status='Draft')
        Meeting.objects.create(department=self.dept, title='Context finished', status='Finished')
        department = self.overview_department_page()
        self.assertEqual([m.pk for m in department.context['meetings']], [self.meeting.pk])
        self.assertContains(department, 'name="q" value="Context"')
        self.assertContains(department, 'value="Draft" selected')
        form = re.search('<form method="get">(.*?)</form>', department.content.decode(), re.S).group(1)
        hidden = unescape(re.search('name="dashboard_context" value="([^"]+)"', form).group(1))
        url = reverse('department_dashboard', args=[self.dept.pk])
        changed = self.client.get(url, {'q': 'Context', 'status': 'Finished', 'dashboard_context': hidden})
        workflow = next(link for link in self.links(changed) if '/review/' in link)
        payload = json.loads(parse_qs(urlsplit(workflow).query)['dashboard_context'][0])
        self.assertEqual(payload['status'], 'Finished')
        self.assertEqual(payload['department'], str(self.dept.pk))
        self.assertNotIn('page', payload)
        self.assertIn(reverse('admin_dashboard') + '?department=' + str(self.dept.pk) + '&q=Context&status=Finished', self.links(self.client.get(workflow)))
        switch = next(link for link in self.links(changed) if urlsplit(link).path == reverse('department_dashboard', args=[self.other.pk]))
        query = parse_qs(urlsplit(switch).query)
        self.assertEqual(query['q'], ['Context'])
        self.assertEqual(query['status'], ['Finished'])
        self.assertNotIn('department', query)
        self.assertNotIn('page', query)
        self.assertEqual(json.loads(query['dashboard_context'][0])['department'], str(self.dept.pk))
        cleared = self.client.get(url, {'q': '', 'status': '', 'dashboard_context': json.dumps(payload)})
        workflow = next(link for link in self.links(cleared) if '/review/' in link)
        payload = json.loads(parse_qs(urlsplit(workflow).query)['dashboard_context'][0])
        self.assertNotIn('q', payload)
        self.assertNotIn('status', payload)
        self.assertIn(reverse('admin_dashboard') + '?department=' + str(self.dept.pk), self.links(self.client.get(workflow)))

    def test_pdf_export_link_carries_context_without_changing_export(self):
        from unittest.mock import patch
        self.client.force_login(self.admin)
        Meeting.objects.filter(pk=self.meeting.pk).update(status='Finished', minutes_content='Final')
        overview = self.client.get(reverse('admin_dashboard'), {'q': 'Context', 'status': 'Finished'})
        entry = next(link for link in self.links(overview) if urlsplit(link).path == reverse('department_dashboard', args=[self.dept.pk]))
        department = self.client.get(entry)
        review = next(link for link in self.links(department) if '/review/' in link)
        page = self.client.get(review)
        export = next(link for link in self.links(page) if '/export/pdf/' in link)
        self.assertIn('dashboard_context', parse_qs(urlsplit(export).query))
        with patch('meetings.pdf.generate_meeting_pdf', return_value=b'%PDF-test'):
            response = self.client.get(export)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'%PDF-test')
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.client.force_login(self.officer)
        self.assertEqual(self.client.get(export).status_code, 403)

    def test_overview_pagination_without_ordinary_filters_preserves_return(self):
        Meeting.objects.bulk_create([Meeting(department=self.dept, title='Context page') for _ in range(22)])
        department = self.overview_department_page()
        workflow = next(link for link in self.links(department) if '/review/' in link)
        saved = parse_qs(urlsplit(workflow).query)['dashboard_context'][0]
        url = reverse('department_dashboard', args=[self.dept.pk])
        paginated = self.client.get(url, {'page': '2', 'dashboard_context': saved})
        self.assertEqual(paginated.context['page_obj'].number, 2)
        workflow = next(link for link in self.links(paginated) if '/review/' in link)
        payload = json.loads(parse_qs(urlsplit(workflow).query)['dashboard_context'][0])
        self.assertEqual(payload['q'], 'Context')
        self.assertEqual(payload['status'], 'Draft')
        self.assertEqual(payload['department'], str(self.dept.pk))
        self.assertEqual(payload['page'], '2')
        self.assertIn(reverse('admin_dashboard') + '?department=' + str(self.dept.pk) + '&q=Context&status=Draft&page=2', self.links(self.client.get(workflow)))
        cleared = self.client.get(url, {'q': '', 'status': '', 'page': '2', 'dashboard_context': json.dumps(payload)})
        workflow = next(link for link in self.links(cleared) if '/review/' in link)
        cleared_context = json.loads(parse_qs(urlsplit(workflow).query)['dashboard_context'][0])
        self.assertNotIn('q', cleared_context)
        self.assertNotIn('status', cleared_context)
        self.assertNotIn('page', cleared_context)
        self.assertEqual(cleared_context['department'], str(self.dept.pk))
