FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose the port used by the client web interface.  This allows
# external browsers to connect to the configuration UI when the
# client runs in its own container.  See docker‑compose files for
# port mappings.
EXPOSE 8080

# The client runs indefinitely, sending backups according to its schedule
CMD ["python", "main.py"]