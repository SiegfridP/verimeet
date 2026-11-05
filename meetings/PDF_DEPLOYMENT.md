# PDF export deployment

The application declares WeasyPrint 70.0 (Python >= 3.10, Pango >= 1.44).
The inspected development environment uses Python 3.15, WeasyPrint 70.0 and
pydyf 0.13.0. No packages were installed for this batch.

Deploy Pango, HarfBuzz/fontconfig and their platform dependencies, plus fonts
covering the languages used in minutes. On Windows the upstream instructions
use MSYS2 UCRT64 Pango; configure WEASYPRINT_DLL_DIRECTORIES for its DLL folder
if it cannot be discovered. On Linux use the distribution's native packages.
See https://doc.courtbouillon.org/weasyprint/stable/first_steps.html.

Smoke-test real rendering on the deployment OS. Missing fonts can produce
missing glyphs even when PDF generation succeeds. Renderer import/native-library
failures return an unavailable response without a successful export event.

Exports use one joined database query to capture current finalized records.
They do not persist artifacts, archive meetings or change signatures. They are
not byte-identical historical snapshots or cryptographically signed PDFs.
No signature profile images or external assets are used; the URL fetcher denies
all resources. Audit records indicate generation/offering, not confirmed delivery.
Large documents consume synchronous rendering resources; configure request
timeouts and deployment resource limits for expected document sizes.
