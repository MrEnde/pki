# syntax=docker/dockerfile:1.4
FROM python:3.10.9-slim-buster

ARG PROJECT_ENV \
  UID=1000 \
  GID=1000

ENV PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PYTHONDONTWRITEBYTECODE=1 \
  # pip:
  PIP_NO_CACHE_DIR=1 \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_DEFAULT_TIMEOUT=100 \
  # poetry:
  POETRY_VERSION=1.3.1 \
  POETRY_NO_INTERACTION=1 \
  POETRY_VIRTUALENVS_CREATE=false \
  POETRY_CACHE_DIR='/var/cache/pypoetry' \
  POETRY_HOME='/usr/local' \
  # dockerize:
  DOCKERIZE_VERSION=v0.6.1 \
  # tini:
  TINI_VERSION=v0.19.0

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

# System deps:
RUN apt-get update && apt-get upgrade -y \
  && apt-get install --no-install-recommends -y \
    curl \
    git \
    build-essential \
    libreoffice  \
    libreoffice-java-common \
    default-jre \
#    socat \
  # Installing `tini` utility:
  # https://github.com/krallin/tini
  # Get architecture to download appropriate tini release:
  # See https://github.com/wemake-services/wemake-django-template/issues/1725 \
  && dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')" \
  && curl -o /usr/local/bin/tini -sSLO "https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-${dpkgArch}" \
  && chmod +x /usr/local/bin/tini && tini --version \
  # Installing `dockerize` utility:
  # https://github.com/jwilder/dockerize
  && curl -sSLO "https://github.com/jwilder/dockerize/releases/download/${DOCKERIZE_VERSION}/dockerize-linux-amd64-${DOCKERIZE_VERSION}.tar.gz" \
  && tar -C /usr/local/bin -xzvf "dockerize-linux-amd64-${DOCKERIZE_VERSION}.tar.gz" \
  && rm "dockerize-linux-amd64-${DOCKERIZE_VERSION}.tar.gz" && dockerize --version \
  # Installing `poetry` package manager:
  # https://github.com/python-poetry/poetry
  && curl -sSL 'https://install.python-poetry.org' | python - \
  && poetry --version \
  # Cleaning cache: \
  && apt-get remove -y cmake \
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && apt-get clean -y && rm -rf /var/lib/apt/lists/*

WORKDIR /code

# Setting up proper permissions:
RUN groupadd -g "${GID}" -r dss \
  && useradd -d '/code' -g dss -m -l -r -u "${UID}" dss \
  && chown dss:dss -R '/code' \
  && mkdir -p '/certomancer/tests/data/keys/' \
  && chown dss:dss '/certomancer/tests/data/keys/' \
  && chmod a+rw '/usr/bin/libreoffice'

COPY --chown=dss:dss ./poetry.lock ./pyproject.toml /code/
COPY --chown=dss:dss . /code/

RUN --mount=type=cache,target="$POETRY_CACHE_DIR" \
  echo "$PROJECT_ENV" \
  && poetry version \
  # Install deps:
  && poetry run pip install -U pip \
  && poetry install \
    $(if [ "$PROJECT_ENV" = 'production' ]; then echo '--only main'; fi) \
    --no-interaction --no-ansi \
  && apt-get remove -y build-essential

COPY ./docker/dss/entrypoint.sh /docker-entrypoint.sh

RUN chmod +x '/docker-entrypoint.sh'

#USER dss

ENTRYPOINT ["tini", "--", "/docker-entrypoint.sh"]