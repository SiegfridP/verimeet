from datetime import datetime
from zoneinfo import ZoneInfo

from django.utils import dateformat, timezone


MANILA = ZoneInfo("Asia/Manila")


def format_pht_datetime(value):
    if not isinstance(value, datetime) or timezone.is_naive(value):
        return ""
    return dateformat.format(timezone.localtime(value, MANILA), "m/d/y, g:i A") + " PHT"
