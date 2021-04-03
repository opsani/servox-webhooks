FROM opsani/servox:edge

COPY . /servo/servox_webhooks

WORKDIR /servo
RUN poetry add /servo/servox_webhooks
RUN poetry install --no-interaction
