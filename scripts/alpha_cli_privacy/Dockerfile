FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace time \
    && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir pydantic==2.14.4 cryptography==46.0.7

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/src/src
