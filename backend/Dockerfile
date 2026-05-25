FROM python:3.11-slim

WORKDIR /app

# Install build dependencies for cryptography package
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements first to leverage Docker layer caching
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir httpx

# Copy the entire workspace so crypto_core and backend are available
COPY . .

EXPOSE 8000

# Run FastAPI under Uvicorn bound to all interfaces
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
