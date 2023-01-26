# syntax=docker/dockerfile:1.4
FROM python:3.10.9-slim

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
  # tini:
  TINI_VERSION=v0.19.0 \
  # OpenSSL
  PREFIX="/usr/local/ssl" \
  ENGINES="/usr/local/ssl/lib/engines-3"

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

# System deps:
RUN apt-get update && apt-get upgrade -y \
  && apt-get install --no-install-recommends -y \
    vim \
    curl \
    git \
    build-essential \
    cmake \
#    socat \
  # Installing `tini` utility:
  # https://github.com/krallin/tini
  # Get architecture to download appropriate tini release:
  # See https://github.com/wemake-services/wemake-django-template/issues/1725 \
  && dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')" \
  && curl -o /usr/local/bin/tini -sSLO "https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-${dpkgArch}" \
  && chmod +x /usr/local/bin/tini && tini --version \
  # Installing `poetry` package manager:
  # https://github.com/python-poetry/poetry
  && curl -sSL 'https://install.python-poetry.org' | python - \
  && poetry --version \
  # Install OpenSSL \
  && cd /usr/local/src \
  && curl --output openssl-3.0.7.tar.gz "https://www.openssl.org/source/openssl-3.0.7.tar.gz" \
  && tar -xf openssl-3.0.7.tar.gz \
  && cd openssl-3.0.7 \
  && chmod +x ./config \
  && ./config -Wl,-Bsymbolic-functions -fPIC shared --prefix=${PREFIX} --openssldir=${PREFIX} --libdir=lib && make -j$(nproc) all && make install_sw \
  && rm /usr/bin/openssl \
  && ln -s "${PREFIX}/bin/openssl" "/usr/bin/openssl" \
  && rm -rf "/usr/local/src/openssl-3.0.7.tar.gz" "/usr/local/src/openssl-3.0.7" \
  && echo "${PREFIX}/lib" >> /etc/ld.so.conf.d/ssl.conf && ldconfig \
  # Install Gost Engine OpenSSL \
  && cd /usr/local/src \
  && git clone "https://github.com/gost-engine/engine" && cd engine \
  && git submodule update --init \
  && mkdir build && cd build \
  && cmake -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR="${PREFIX}" -DOPENSSL_ENGINES_DIR="${ENGINES}" .. \
  && cmake --build . --config Release \
  && cmake --build . --target install --config Release \
  && rm -rf "/usr/local/src/engine" \
  # Cleaning cache: \
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false cmake \
  && apt-get clean -y && rm -rf /var/lib/apt/lists/*

COPY "./docker/ca/openssl.cnf" "/${PREFIX}/openssl.cnf"

WORKDIR /code

# Setting up proper permissions:
RUN groupadd -g "${GID}" -r ca \
  && useradd -d '/certomancer' -g ca -l -r -u "${UID}" ca \
  && chown ca:ca -R '/code' \
  && mkdir -p '/certomancer/tests/data/keys/' \
  && chown ca:ca '/certomancer/tests/data/keys/'

COPY --chown=ca:ca ./poetry.lock ./pyproject.toml /code/
COPY --chown=ca:ca . /code/

RUN --mount=type=cache,target="$POETRY_CACHE_DIR" \
  echo "$PROJECT_ENV" \
  && poetry version \
  # Install deps:
  && poetry run pip install -U pip \
  && poetry install \
    $(if [ "$PROJECT_ENV" = 'production' ]; then echo '--only main'; fi) \
    --no-interaction --no-ansi \
  && apt-get purge -y --auto-remove build-essential

COPY ./docker/ca/entrypoint.sh /docker-entrypoint.sh

RUN chmod +x '/docker-entrypoint.sh'

USER ca

ENTRYPOINT ["tini", "--", "/docker-entrypoint.sh"]
