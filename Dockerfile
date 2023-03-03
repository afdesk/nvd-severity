FROM --platform=linux/amd64 python:3.9-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VERSION=1.3.2 \
    POETRY_NO_INTERACTION=1 \
    POETRY_INSTALL_OPTS="--no-interaction --no-dev --no-root" \
    PYSETUP_PATH="/pysetup" \
    VENV_PATH="/pysetup/.venv"

ENV PATH="${VENV_PATH}/bin:${PATH}"

COPY . $PYSETUP_PATH
WORKDIR $PYSETUP_PATH
RUN pip install "poetry==${POETRY_VERSION}" && \
    poetry install $POETRY_INSTALL_OPTS && \
    poetry build && \
    $VENV_PATH/bin/pip install --no-deps dist/*.whl

RUN ln -fns /usr/bin/python $VENV_PATH/bin/python

#Python version - 3.9.2 nonroot
FROM --platform=linux/amd64 gcr.io/distroless/python3@sha256:a66e582f67df92987039ad8827f0773f96020661c7ae6272e5ab80e2d3abc897

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VENV_PATH="/pysetup/.venv"

COPY --from=builder $VENV_PATH $VENV_PATH

ENV PATH="${VENV_PATH}/bin:${PATH}"

USER nonroot

ENTRYPOINT ["nvd-severity"]