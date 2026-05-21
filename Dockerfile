FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
COPY eval ./eval

RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /install /usr/local
COPY src ./src
COPY eval ./eval
COPY data/raw ./data/raw

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD security-rag status || exit 1

ENTRYPOINT ["security-rag"]
CMD ["--help"]
