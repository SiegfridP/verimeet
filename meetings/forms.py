from django import forms
from django.db import models
from django.contrib.auth import get_user_model
from .models import Meeting, Attendance
from accounts.models import Membership, Department

User = get_user_model()

class MeetingForm(forms.ModelForm):
    participants = forms.ModelMultipleChoiceField(
        queryset=User.objects.none(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
        label="Assigned Participants & Signers",
        help_text="Select department members to assign as participants and intended signers."
    )

    class Meta:
        model = Meeting
        fields = ['title', 'minutes_content']
        labels = {
            'title': 'Meeting Title / Subject',
            'minutes_content': 'Agenda / Initial Minutes',
        }
        widgets = {
            'title': forms.TextInput(attrs={
                'placeholder': 'e.g. Regular Departmental Assembly',
                'id': 'id_title',
            }),
            'minutes_content': forms.Textarea(attrs={
                'placeholder': 'Meeting agenda, notes, or initial draft of minutes...',
                'rows': 6,
                'id': 'id_minutes_content',
            }),
        }
        error_messages = {
            'title': {
                'required': 'Meeting title is required.',
            }
        }

    def __init__(self, *args, department=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.department = department
        if department:
            self.fields['participants'].queryset = User.objects.filter(
                models.Q(memberships__department=department) | models.Q(department=department),
                is_active=True
            ).distinct().order_by('username')
            self.fields['participants'].label_from_instance = (
                lambda user: f"{user.username} ({user.email})" if user.email else user.username
            )

    def clean_title(self):
        title = self.cleaned_data.get('title', '').strip()
        if not title:
            raise forms.ValidationError("Meeting title is required.")
        return title

    def clean_participants(self):
        participants = self.cleaned_data.get('participants')
        if not self.department:
            raise forms.ValidationError("Department context is required.")
        if participants:
            for user in participants:
                is_member = (
                    user.is_active and (
                        Membership.objects.filter(user=user, department=self.department).exists() or
                        user.department_id == self.department.id
                    )
                )
                if not is_member:
                    raise forms.ValidationError(f"User {user} is not an eligible member of {self.department.name}.")
        return participants


class AssignParticipantsForm(forms.Form):
    participants = forms.ModelMultipleChoiceField(
        queryset=User.objects.none(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
        label="Assigned Participants & Signers",
        help_text="Select department members to assign as participants and intended signers."
    )

    def __init__(self, *args, department=None, meeting=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.department = department
        self.meeting = meeting
        if department:
            self.fields['participants'].queryset = User.objects.filter(
                models.Q(memberships__department=department) | models.Q(department=department),
                is_active=True
            ).distinct().order_by('username')
            self.fields['participants'].label_from_instance = (
                lambda user: f"{user.username} ({user.email})" if user.email else user.username
            )

    def clean_participants(self):
        participants = self.cleaned_data.get('participants')
        if not self.department:
            raise forms.ValidationError("Department context is required.")
        if participants:
            for user in participants:
                is_member = (
                    user.is_active and (
                        Membership.objects.filter(user=user, department=self.department).exists() or
                        user.department_id == self.department.id
                    )
                )
                if not is_member:
                    raise forms.ValidationError(f"User {user} is not an eligible member of {self.department.name}.")
        return participants
