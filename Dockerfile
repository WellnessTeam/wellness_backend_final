# Dockerfile for Wellnessapp (main API)
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy the pyproject.toml, poetry.lock, file
COPY pyproject.toml poetry.lock  /app/

# Install dependenciess using Poetry
RUN poetry config virtualenvs.create false && poetry install --no-interaction --no-ansi

# Copy the rest of the application code
COPY app /app

# Run the FastAPI app
CMD ["uvicorn", "main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"]