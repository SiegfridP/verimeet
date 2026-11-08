FROM python:3.14-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 libffi8 fonts-dejavu-core fonts-noto-core && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Static collection uses development-only configuration; no deployment secrets enter layers.
RUN COLLECT_STATIC=1 DJANGO_ENV=development DJANGO_SECRET_KEY=build-only-not-a-deployment-secret python manage.py collectstatic --noinput
RUN useradd --uid 10001 --create-home app
USER app
CMD ["sh", "-c", "python manage.py migrate --noinput && exec gunicorn core.wsgi:application --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 1 --timeout 120 --access-logfile -"]
