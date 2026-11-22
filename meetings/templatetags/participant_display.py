from django import template
from meetings.reading import participant_name

register = template.Library()


@register.filter
def participant_display(user):
    return participant_name(user.first_name, user.last_name, user.username)
