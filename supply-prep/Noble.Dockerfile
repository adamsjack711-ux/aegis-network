FROM mcr.microsoft.com/playwright/python:v1.50.0-noble
COPY python /opt/cpython313
ENV PATH=/opt/cpython313/bin:$PATH
