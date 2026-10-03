# hitl server. The repository is mounted read-only at /app (see docker-compose.example.yml),
# so a deploy is a git pull; this image carries only the runtime.
FROM python:3.12-slim

# The locked versions, each checked against its hash.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HITL_BIND=0.0.0.0
WORKDIR /app/server
USER www-data
EXPOSE 8080
CMD ["gunicorn", "-c", "/app/deploy/gunicorn.conf.py", "hitl.app:application"]
