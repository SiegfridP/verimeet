"""Presentation-only normalization for untrusted labels in plain-text email."""
import unicodedata

from django import template

register = template.Library()


@register.filter
def email_text_label(value):
    """Keep labels on one line; remove control and directional formatting effects.

    URLs are not labels and must not pass through this filter.
    No HTML safety flag is applied: HTML templates still escape the result.
    """
    text = "".join(
        " " if unicodedata.category(char).startswith("C") or char.isspace() else char
        for char in str(value)
    )
    return " ".join(text.split())
