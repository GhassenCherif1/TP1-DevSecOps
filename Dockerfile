FROM python:3.10-slim

# Create a working directory
WORKDIR /app

# Copy server script
COPY dsvw.py .

# Expose port
EXPOSE 8000

# Run the server
CMD ["python", "server.py"]
