FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first so code edits do not invalidate the wheel cache.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8000

# Bound to 0.0.0.0 so the container is reachable from the host and from a phone
# on the same network.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
