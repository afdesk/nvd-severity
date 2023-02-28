FROM --platform=linux/amd64 python:3.11.2-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VERSION=1.3.2 \
    POETRY_NO_INTERACTION=1 \
    POETRY_INSTALL_OPTS="--no-interaction --no-dev --no-root"

ENV PATH="${POETRY_HOME}/bin:${PATH}"

RUN apt-get update \
    && apt-get install --no-install-recommends -y curl build-essential \
    && curl -sSL https://install.python-poetry.org | POETRY_HOME=$POETRY_HOME python3 - --version $POETRY_VERSION \
    && python -m venv /venv

WORKDIR /app

ENV PATH="/app/.venv/bin:$PATH"

COPY poetry.lock pyproject.toml /app/

RUN poetry install --only=main --no-root


FROM --platform=linux/amd64 python:3.11.2-slim-bullseye

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get install -y --no-install-recommends git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/.venv ./venv
COPY . ./

ENV PATH="/app/venv/bin:$PATH"

STOPSIGNAL SIGINT

CMD ["/app/venv/bin/python", "-m", "nvd_severity"]