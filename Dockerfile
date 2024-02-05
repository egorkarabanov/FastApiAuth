FROM python:3.11

WORKDIR /usr/src/app

ENV PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1

ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN pip install "poetry"

ENV PATH="${PATH}:/root/.poetry/bin"

COPY . .

RUN poetry config virtualenvs.create false
RUN poetry install --no-interaction --no-ansi

