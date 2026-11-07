"""Allowlisted dashboard navigation state; never a source of authority."""
import json
from urllib.parse import urlencode

from django.shortcuts import redirect
from django.urls import reverse

from .models import Department, Membership


FILTER_CHOICES = {
    'status': ('Draft', 'Finished', 'Archived'),
    'assignment': ('assigned', 'unassigned'),
    'attendance': ('Attended', 'Late', 'Absent'),
    'signing': ('signed', 'eligible', 'awaiting', 'unavailable'),
}


def department_allowed(user, department):
    from .views import is_global_admin
    return (is_global_admin(user)
            or Membership.objects.filter(user=user, department=department).exists()
            or (user.department_id == department.pk
                and not Membership.objects.filter(user=user).exists()))


def number(value, limit=9):
    value = str(value)
    return int(value) if value.isascii() and value.isdecimal() and len(value) <= limit and int(value) > 0 else None


def overview_department(value):
    """Empty selects all; invalid selections stay empty-result via canonical zero."""
    if value is None or value == '':
        return ''
    pk = number(value)
    return str(pk) if pk and Department.objects.filter(pk=pk).exists() else '0'


def incoming_context(request):
    raw = request.POST.get('dashboard_context', request.GET.get('dashboard_context', ''))
    if not isinstance(raw, str) or len(raw) > 2000:
        return None
    try:
        return validate_context(request, json.loads(raw))
    except (ValueError, TypeError):
        return None


def context(request):
    if not request.user.is_authenticated:
        return None
    match = request.resolver_match
    if request.method == 'GET' and match and match.url_name in ('admin_dashboard', 'department_dashboard'):
        if match.url_name == 'department_dashboard':
            incoming = incoming_context(request)
            if incoming and incoming['kind'] == 'overview':
                # Explicit filters override saved values; absence preserves them.
                updated = incoming.copy()
                for key in ('q', 'status'):
                    if key in request.GET:
                        updated[key] = request.GET[key]
                updated = validate_context(request, updated)
                if any(updated.get(key) != incoming.get(key) for key in ('q', 'status')):
                    updated.pop('page', None)
                elif 'page' in request.GET:
                    updated['page'] = request.GET['page']
                return validate_context(request, updated)
        data = dict(request.GET.items())
        data['kind'] = 'overview' if match.url_name == 'admin_dashboard' else 'department'
        data['dept'] = match.kwargs.get('dept_id')
    else:
        return incoming_context(request)
    return validate_context(request, data)


def validate_context(request, data):
    from .views import is_global_admin
    if not request.user.is_authenticated:
        return None
    if not isinstance(data, dict) or data.get('kind') not in ('overview', 'department'):
        return None
    result = {'kind': data['kind']}
    officer = False
    if data['kind'] == 'overview':
        if not is_global_admin(request.user):
            return None
        department = overview_department(data.get('department'))
        if department:
            result['department'] = str(department)
    else:
        pk = number(data.get('dept'))
        department = Department.objects.filter(pk=pk, is_active=True).first() if pk else None
        if not department or not department_allowed(request.user, department):
            return None
        result['dept'] = department.pk
        officer = not (is_global_admin(request.user) or Membership.objects.filter(
            user=request.user, department=department, role='AP').exists())
    q = data.get('q', '')
    if isinstance(q, str) and q.strip():
        result['q'] = q.strip()[:200]
    for key, allowed in FILTER_CHOICES.items():
        if (key == 'status' or officer) and data.get(key) in allowed:
            result[key] = data[key]
    page = number(data.get('page'), limit=6)
    if page:
        result['page'] = str(page)
    return result


def packed(data):
    return json.dumps(data, separators=(',', ':'))


def destination(data, reset=False):
    url = reverse('admin_dashboard') if data['kind'] == 'overview' else reverse(
        'department_dashboard', kwargs={'dept_id': data['dept']})
    params = {k: v for k, v in data.items() if k not in ('kind', 'dept') and not (reset and k == 'page')}
    return url + ('?' + urlencode(params) if params else '')


def workflow_url(request, name, args=(), kwargs=None, reset=False):
    data = context(request)
    if data and name in ('admin_dashboard', 'department_dashboard', 'routing_view'):
        return destination(data, reset)
    url = reverse(name, args=args, kwargs=kwargs)
    if data:
        if reset:
            data.pop('page', None)
        url += '?' + urlencode({'dashboard_context': packed(data)})
    return url


def workflow_redirect(request, name, **kwargs):
    return redirect(workflow_url(request, name, kwargs=kwargs, reset=True))


def dashboard_entry(request, dept_id):
    """Enter a selected department, rather than resolving a return destination."""
    url = reverse('department_dashboard', kwargs={'dept_id': dept_id})
    data = context(request)
    params = {}
    if data and data['kind'] == 'overview':
        data.pop('page', None)
        params.update({key: data[key] for key in ('q', 'status') if key in data})
        params['dashboard_context'] = packed(data)
    elif data:
        params = {k: v for k, v in data.items() if k not in ('kind', 'dept', 'page')}
    return url + ('?' + urlencode(params) if params else '')
