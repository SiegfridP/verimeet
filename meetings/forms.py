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


class MeetingEditForm(forms.ModelForm):
    class Meta:
        model = Meeting
        fields = ['title', 'minutes_content']
        labels = {
            'title': 'Meeting Title / Subject',
            'minutes_content': 'Agenda / Minutes Content',
        }
        widgets = {
            'title': forms.TextInput(attrs={
                'placeholder': 'e.g. Regular Departmental Assembly',
                'id': 'id_title',
            }),
            'minutes_content': forms.Textarea(attrs={
                'placeholder': 'Meeting agenda, notes, or minutes content...',
                'rows': 8,
                'id': 'id_minutes_content',
            }),
        }
        error_messages = {
            'title': {
                'required': 'Meeting title is required.',
            }
        }

    def clean_title(self):
        title = self.cleaned_data.get('title', '').strip()
        if not title:
            raise forms.ValidationError("Meeting title is required.")
        return title

    def clean(self):
        cleaned_data = super().clean()
        if self.instance and self.instance.pk and self.instance.status in ('Finished', 'Archived'):
            raise forms.ValidationError("Cannot edit a locked or finalized meeting.")
        return cleaned_data


MAX_ANNOTATION_LENGTH = 2000


class AttendanceStatusUpdateForm(forms.Form):
    status = forms.ChoiceField(
        choices=Attendance.ATTENDANCE_STATUS_CHOICES,
        required=True,
        error_messages={
            'required': 'Attendance status is required.',
            'invalid_choice': 'Select a valid attendance status.',
        }
    )

    def clean_status(self):
        status = self.cleaned_data.get('status')
        valid_statuses = [choice[0] for choice in Attendance.ATTENDANCE_STATUS_CHOICES]
        if status not in valid_statuses:
            raise forms.ValidationError("Select a valid attendance status.")
        return status


class SignMeetingForm(forms.Form):
    annotation = forms.CharField(
        widget=forms.Textarea(attrs={
            'rows': 4,
            'placeholder': 'Add an optional annotation, concurrence note, or comment...',
            'maxlength': str(MAX_ANNOTATION_LENGTH),
            'id': 'id_annotation',
        }),
        required=False,
        max_length=MAX_ANNOTATION_LENGTH,
        strip=False,
        help_text=f"Optional annotation (max {MAX_ANNOTATION_LENGTH} characters). Permanently bound to your digital signature."
    )

    def clean_annotation(self):
        annotation = self.cleaned_data.get('annotation', '')
        if len(annotation) > MAX_ANNOTATION_LENGTH:
            raise forms.ValidationError(
                f"Annotation exceeds maximum allowed length of {MAX_ANNOTATION_LENGTH} characters."
            )
        return annotation
