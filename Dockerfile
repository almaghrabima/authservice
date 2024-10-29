# Dockerfile
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy requirements and install them
COPY auth-requirements.txt .
RUN pip install --no-cache-dir -r auth-requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "authmain:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
