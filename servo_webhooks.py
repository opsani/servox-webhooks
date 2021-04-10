from __future__ import annotations
import hmac
import hashlib
import datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Dict, List, Optional

import httpx
import pydantic
import devtools
from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, validator

import servo
from servo import metadata, License, Maturity, Duration
from servo.events import (
    EventContext,
    EventResult,
    Preposition,
    validate_event_contexts
)


try:
    __version__ = version("servo-webhooks")
except PackageNotFoundError:
    __version__ = "0.0.0"


SUCCESS_STATUS_CODES = (
    httpx.codes.OK,
    httpx.codes.CREATED,
    httpx.codes.ACCEPTED,
    httpx.codes.NO_CONTENT,
    httpx.codes.ALREADY_REPORTED
)
CONTENT_TYPE = "application/vnd.opsani.servo-webhooks+json"


class BackoffConfig(BaseModel):
    """
    The BackoffConfig class provides configuration for backoff and retry provided
    by the backoff library.
    """
    max_time: Duration = '3m'
    max_tries: int = 12


class Webhook(servo.BaseConfiguration):
    name: Optional[str] = Field(
        description="A unique name identifying the webhook.",
    )
    description: Optional[str] = Field(
        description="Optional free-form text describing the context or purpose of the webhook.",
    )
    events: List[str] = Field(
        [],
        description="A list of events that the webhook is listening for.",
    )
    channels: List[servo.pubsub.ChannelName] = Field(
        [],
        description="A list of channels that the webhook is subscribed to.",
    )
    response_channel: Optional[str] = Field(
        description="The channel to publish webhook responses to.",
    )
    url: AnyHttpUrl = Field(
        description="An HTTP, HTTPS, or HTTP/2 endpoint listening for webhooks event requests.",
    )
    secret: SecretStr = Field(
        description="A secret string value used to produce an HMAC digest for verifying webhook authenticity.",
    )
    headers: Dict[str, str] = Field(
        {},
        description="A dictionary of supplemental HTTP headers to include in webhook requests.",
    )
    backoff: BackoffConfig = BackoffConfig()

    @validator("events", "channels", pre=True)
    def _coerce_single_event_to_list(cls, v):
        if isinstance(v, str):
            return [v]
        return v

    # Map strings from config into EventContext objects
    _validate_events = validator("events", pre=True, allow_reuse=True)(validate_event_contexts)

    @pydantic.root_validator(skip_on_failure=True)
    @classmethod
    def _validate_has_events_or_channels(cls, values: dict) -> Dict[str, Any]:
        events, channels = values["events"], values["channels"]
        if len(events) == 0 and len(channels) == 0:
            raise ValueError(
                f"missing webhook data source: events and channels cannot both be empty"
            )

        return values


class WebhooksConfiguration(servo.AbstractBaseConfiguration):
    __root__: List[Webhook] = []

    @classmethod
    def generate(cls, **kwargs) -> "WebhooksConfiguration":
        return cls(
            __root__=[
                Webhook(
                    name="My Webhook",
                    description="Listens for after:measure events and sends an email",
                    events=["after:measure"],
                    url="https://example.com/",
                    secret="s3cr3t!"
                )
            ],
            **kwargs,
        )

    @property
    def webhooks(self) -> List[Webhook]:
        """
        Convenience method for retrieving the root type as a list of webhooks.
        """
        return self.__root__


class Result(BaseModel):
    """Models an EventResult webhook representation"""
    connector: str
    value: Any


class RequestBody(BaseModel):
    """Models the JSON body of a webhook request containing event results"""
    event: str
    created_at: datetime.datetime = pydantic.Field(default_factory=datetime.datetime.now)
    results: Optional[List[Result]] = None


@metadata(
    name=("servo-webhooks", "webhooks"),
    description="Dispatch servo events via HTTP webhooks",
    version=__version__,
    homepage="https://github.com/opsani/servo-webhooks",
    license=License.apache2,
    maturity=Maturity.experimental,
)
class WebhooksConnector(servo.BaseConnector):
    config: WebhooksConfiguration

    @servo.on_event()
    async def startup(self) -> None:
        self._register_event_handlers()
        self._register_subscriber_handlers()

    ##
    # Event Webhooks

    def _register_event_handlers(self) -> None:
        for webhook in self.config.webhooks:
            for event_name in webhook.events:
                event = EventContext.from_str(event_name)
                if not event:
                    raise ValueError(f"invalid webhook event '{event_name}'")
                if event.preposition == Preposition.before:
                    self._add_before_event_webhook_handler(webhook, event)
                elif event.preposition == Preposition.after:
                    self._add_after_event_webhook_handler(webhook, event)
                else:
                    raise ValueError(f"Unsupported Preposition value given for webhook: '{event.preposition}'")

    def _add_before_event_webhook_handler(self, webhook: Webhook, event: EventContext) -> None:
        async def __before_handler(self) -> None:
            headers = {**webhook.headers, **{ "Content-Type": CONTENT_TYPE }}
            async with httpx.AsyncClient(headers=headers) as client:
                body = RequestBody(event=str(event))
                json_body = body.json()
                headers["X-Servo-Signature"] = _signature_for_webhook_body(webhook, json_body)
                async with httpx.AsyncClient(headers=headers) as client:
                    try:
                        response = await client.post(webhook.url, data=json_body, headers=headers)
                        success = (response.status_code in SUCCESS_STATUS_CODES)
                        if success:
                            self.logger.success(f"posted webhook for '{event}' event to '{webhook.url}' ({response.status_code} {response.reason_phrase})")
                        else:
                            self.logger.error(f"failed posted webhook for '{event}' event to '{webhook.url}' ({response.status_code} {response.reason_phrase}): {response.text}")

                        await self._publish_response_if_necessary(response, webhook)

                    except (httpx.RequestError, httpx.HTTPError) as error:
                        self.logger.error(f"HTTP error \"{error.__class__.__name__}\" encountered while posting to webhook \"{webhook.url}\": {error}")
                        self.logger.trace(f"Webhook: {devtools.pformat(webhook)}, request body={devtools.pformat(json_body)}")

        self.add_event_handler(event.event, event.preposition, __before_handler)

    def _add_after_event_webhook_handler(self, webhook: Webhook, event: EventContext) -> None:
        async def __after_handler(self, results: List[EventResult], **kwargs) -> None:
            headers = {**webhook.headers, **{ "Content-Type": CONTENT_TYPE }}

            outbound_results = []
            for result in results:
                outbound_results.append(
                    Result(
                        connector=result.connector.name,
                        value=result.value
                    )
                )
            body = RequestBody(
                event=str(event),
                results=outbound_results
            )

            json_body = body.json()
            headers["X-Servo-Signature"] = _signature_for_webhook_body(webhook, json_body)
            async with httpx.AsyncClient(headers=headers) as client:
                try:
                    response = await client.post(webhook.url, data=json_body, headers=headers)
                    success = (response.status_code in SUCCESS_STATUS_CODES)
                    if success:
                        self.logger.success(f"posted webhook for '{event}' event to '{webhook.url}' ({response.status_code} {response.reason_phrase})")
                    else:
                        self.logger.error(f"failed posted webhook for '{event}' event to '{webhook.url}' ({response.status_code} {response.reason_phrase}): {response.text}")

                    await self._publish_response_if_necessary(response, webhook)

                except (httpx.RequestError, httpx.HTTPError) as error:
                    self.logger.error(f"HTTP error \"{error.__class__.__name__}\" encountered while posting to webhook \"{webhook.url}\": {error}")
                    self.logger.trace(f"Webhook: {devtools.pformat(webhook)}, request body={devtools.pformat(json_body)}")

        self.add_event_handler(event.event, event.preposition, __after_handler)

    ##
    # Pub/sub Webhooks

    def _register_subscriber_handlers(self) -> None:
        for webhook in self.config.webhooks:
            for channel in webhook.channels:
                self._add_subscriber_for_webhook_channel(webhook, channel)

    def _add_subscriber_for_webhook_channel(self, webhook: Webhook, channel: str) -> None:
        @self.subscribe(channel)
        async def _message_received(message: servo.Message, channel: servo.Channel) -> None:
            servo.logger.debug(f"Notified of a new Message: {message}, {channel}")

            headers = {**webhook.headers, **{ "Content-Type": CONTENT_TYPE }}
            headers["X-Servo-Signature"] = _signature_for_webhook_body(webhook, message.text)
            async with httpx.AsyncClient(headers=headers) as client:
                try:
                    response = await client.post(webhook.url, data=message.content, headers=headers)
                    success = (response.status_code in SUCCESS_STATUS_CODES)
                    if success:
                        self.logger.success(f"posted webhook for message sent to '{channel}' sent to '{webhook.url}' ({response.status_code} {response.reason_phrase})")
                    else:
                        self.logger.error(f"failed posted webhook for message sent to '{channel}' event to '{webhook.url}' ({response.status_code} {response.reason_phrase}): {response.text}")

                    await self._publish_response_if_necessary(response, webhook)

                except (httpx.RequestError, httpx.HTTPError) as error:
                    self.logger.error(f"HTTP error \"{error.__class__.__name__}\" encountered while posting to webhook \"{webhook.url}\": {error}")
                    self.logger.trace(f"Webhook: {devtools.pformat(webhook)}, request body={devtools.pformat(json_body)}")

    async def _publish_response_if_necessary(self, response: httpx.Response, webhook: Webhook) -> None:
        # Only publish successful responses for the moment
        if not response.status_code in SUCCESS_STATUS_CODES:
            return

        content_type = response.headers.get("Content-Type")
        if content_type is None:
            return

        if len(response.content) and webhook.response_channel:
            async with self.publish(webhook.response_channel) as publisher:
                message = servo.Message(content=response.content, content_type=content_type)
                self.logger.info(f"Publishing response message to channel '{webhook.response_channel}': {message}")
                await publisher(message)


def _signature_for_webhook_body(webhook: Webhook, body: str) -> str:
    secret_bytes = webhook.secret.get_secret_value().encode()
    return str(hmac.new(secret_bytes, body.encode(), hashlib.sha1).hexdigest())


# class CLI(servo.cli.ConnectorCLI):
#     pass
#     # list, add, remove, test
