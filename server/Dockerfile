FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

COPY . /app/server

EXPOSE 8000

# Use gunicorn or uvicorn for FastAPI
# Run the FastAPI application as a module so that relative imports work
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
