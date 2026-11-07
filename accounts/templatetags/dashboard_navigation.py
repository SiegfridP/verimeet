from django import template
from django.utils.html import format_html
from urllib.parse import urlencode
from accounts.dashboard_context import context as dashboard_context, packed, workflow_url, dashboard_entry

register = template.Library()


@register.simple_tag(takes_context=True)
def dashboard_url(context, name, *args, **kwargs):
    return workflow_url(context['request'], name, args=args, kwargs=kwargs)


@register.simple_tag(takes_context=True)
def dashboard_field(context, reset=False):
    data = dashboard_context(context['request'])
    if data:
        if reset:
            data.pop('page', None)
        return format_html('<input type="hidden" name="dashboard_context" value="{}">', packed(data))
    return ''


@register.simple_tag(takes_context=True)
def dashboard_query(context):
    data = dashboard_context(context['request'])
    return urlencode({'dashboard_context': packed(data)}) if data else ''


@register.simple_tag(takes_context=True)
def dashboard_entry_url(context, dept_id):
    return dashboard_entry(context['request'], dept_id)


@register.simple_tag(takes_context=True)
def overview_url(context):
    from django.urls import reverse
    from accounts.dashboard_context import destination
    data = dashboard_context(context['request'])
    return destination(data) if data and data['kind'] == 'overview' else reverse('admin_dashboard')
