from django import forms
from django.db import models
from django.contrib.auth import get_user_model
from .models import Meeting, Attendance
from accounts.models import Membership, Department

User = get_user_model()


def participant_choices(department, meeting=None):
    """New assignments follow membership precedence; existing records may be retained."""
    if not department or not Department.objects.filter(pk=department.pk, is_active=True).exists():
        return User.objects.none()
    memberships = Membership.objects.filter(user_id=models.OuterRef('pk'))
    users = User.objects.alias(
        has_memberships=models.Exists(memberships),
        joined=models.Exists(memberships.filter(department_id=department.pk)))
    if meeting and meeting.pk and meeting.department_id == department.pk:
        users = users.annotate(existing_assignment=models.Exists(
            Attendance.objects.filter(meeting_id=meeting.pk, user_id=models.OuterRef('pk'))))
    else:
        users = users.annotate(existing_assignment=models.Value(False, output_field=models.BooleanField()))
    eligible = models.Q(joined=True) | models.Q(has_memberships=False, department_id=department.pk)
    return users.filter((models.Q(is_active=True) & eligible) |
                        models.Q(existing_assignment=True)).order_by('username')


def participant_label(user):
    label = f"{user.username} ({user.email})" if user.email else user.username
    if not user.is_active:
        return label + ' - Inactive, already assigned; deselect to remove'
    return label + (' - Already assigned' if user.existing_assignment else '')


class ParticipantSelectionMixin:
    def clean_participants(self):
        participants = self.cleaned_data.get('participants')
        if not self.department or not Department.objects.filter(pk=self.department.pk, is_active=True).exists():
            raise forms.ValidationError('An active department is required.')
        selected = {user.pk for user in participants} if participants is not None else set()
        current = set(participant_choices(self.department, getattr(self, 'meeting', None))
                      .filter(pk__in=selected).values_list('pk', flat=True))
        if selected != current:
            raise forms.ValidationError('Participant eligibility changed. Refresh before trying again.')
        return participants


class MeetingForm(ParticipantSelectionMixin, forms.ModelForm):
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
            self.fields['participants'].queryset = participant_choices(department)
            self.fields['participants'].label_from_instance = participant_label

    def clean_title(self):
        title = self.cleaned_data.get('title', '').strip()
        if not title:
            raise forms.ValidationError("Meeting title is required.")
        return title

class AssignParticipantsForm(ParticipantSelectionMixin, forms.Form):
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
            self.fields['participants'].queryset = participant_choices(department, meeting)
            self.fields['participants'].label_from_instance = participant_label


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
