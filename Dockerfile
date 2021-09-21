FROM opsani/servox:v0.10.7
# note: keep the servox version equal to the one in pyproject.toml

WORKDIR /servo/servox_webhooks
COPY poetry.lock pyproject.toml README.md CHANGELOG.md ./

# cache dependency install (without full sources)
RUN pip install poetry==1.1.* \
  && poetry install \
  $(if [ "$SERVO_ENV" = 'production' ]; then echo '--no-dev'; fi) \
    --no-interaction

# copy the full sources
COPY . ./

# install (it won't install unless the source is present)
RUN poetry install \
  $(if [ "$SERVO_ENV" = 'production' ]; then echo '--no-dev'; fi) \
    --no-interaction \
  # Clean poetry cache for production
  && if [ "$SERVO_ENV" = 'production' ]; then rm -rf "$POETRY_CACHE_DIR"; fi

# reset workdir for servox entrypoints
WORKDIR /servo
