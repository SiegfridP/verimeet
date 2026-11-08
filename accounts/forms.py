from django import forms
from allauth.account.adapter import get_adapter
from .models import User
from .signatures import validate_signature_upload


class SignatureReplacementForm(forms.Form):
    signature = forms.FileField(validators=[validate_signature_upload])
    confirm = forms.BooleanField(label='I confirm replacement; previous PNG versions will be retained.')
    version = forms.CharField(widget=forms.HiddenInput, max_length=512)


def clean_account_username(value, user):
    get_adapter().clean_username(value, shallow=True)
    if User.objects.filter(username__iexact=value).exclude(pk=user.pk).exists():
        raise forms.ValidationError('This username is already in use.')
    return value


class UsernameSettingsForm(forms.Form):
    username = forms.CharField(max_length=150, label='Username')

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.fields['username'].initial = user.username

    def clean_username(self):
        return clean_account_username(self.cleaned_data['username'], self.user)


class OnboardingForm(forms.Form):
    username = forms.CharField(max_length=150)
    signature = forms.FileField(label='PNG signature')

    def __init__(self, *args, user, needs_signature, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        if not user.username_confirmation_required and user.username:
            self.fields.pop('username')
        else:
            self.fields['username'].initial = user.username
        if not needs_signature:
            self.fields.pop('signature')

    def clean_username(self):
        return clean_account_username(self.cleaned_data['username'], self.user)

    def clean_signature(self):
        upload = self.cleaned_data['signature']
        validate_signature_upload(upload)
        return upload
