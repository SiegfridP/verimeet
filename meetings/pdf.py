from django.template.loader import render_to_string
from django.core.files.base import ContentFile
import weasyprint

def generate_meeting_pdf(meeting):
    """Takes a meeting and its attendees, renders HTML, and creates a PDF."""
    attendees = meeting.attendees.filter(has_signed=True)
    
    # Render the strict PDF template with the meeting data and signatures
    html_string = render_to_string('pdf/final_minutes.html', {
        'meeting': meeting,
        'attendees': attendees
    })
    
    # Convert HTML to PDF using WeasyPrint
    pdf_file = weasyprint.HTML(string=html_string).write_pdf()
    
    # In a real app, you would save this `pdf_file` (bytes) to an AWS S3 bucket 
    # or a FileField on the Meeting model.
    return pdf_file