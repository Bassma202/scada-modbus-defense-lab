FROM python:3.12.8-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 1001 aether && useradd --uid 1001 --gid 1001 --create-home aether
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY evidence/ ./evidence/
RUN pip install --no-cache-dir .

USER 1001:1001
EXPOSE 8001
CMD ["uvicorn", "aether.web:app", "--host", "0.0.0.0", "--port", "8001"]
