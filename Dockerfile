FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (needed for some python libs)
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the port defined in .env or default to 8000
ENV PORT=8000
EXPOSE $PORT

# Run the application
# Using uvicorn with --host 0.0.0.0 to allow external access
CMD ["uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8000"]
