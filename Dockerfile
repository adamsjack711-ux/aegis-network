FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .
RUN useradd --create-home aegis && mkdir /audit && chown aegis:aegis /audit
USER aegis
CMD ["uvicorn", "aegis.api:app", "--host", "0.0.0.0", "--port", "8000"]
