FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY eval ./eval

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["security-rag"]
CMD ["--help"]
