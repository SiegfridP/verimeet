from django import template

from core.display_time import format_pht_datetime


register = template.Library()
register.filter("pht_datetime", format_pht_datetime)
