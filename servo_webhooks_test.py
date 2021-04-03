from __future__ import annotations
import asyncio
import hmac
import hashlib
from typing import List, Optional, AsyncIterator

import pydantic
import pytest
import servo
from servo import BaseConfiguration, BaseConnector, Metric, Unit, on_event
from servo.events import EventContext
from servo_webhooks import WebhooksConfiguration, WebhooksConnector, Webhook, __version__
import httpx
import respx
import fastapi
import uvicorn

pytestmark = pytest.mark.asyncio

class WebhookEventConnector(BaseConnector):
    @on_event()
    def metrics(self) -> List[Metric]:
        return [
            Metric("throughput", Unit.requests_per_minute),
            Metric("error_rate", Unit.percentage),
        ]

@respx.mock
async def test_webhook() -> None:
    webhook = Webhook(url="http://localhost:8080/webhook", events="before:measure", secret="testing")
    config = WebhooksConfiguration(__root__=[webhook])
    connector = WebhooksConnector(config=config)
    await connector.startup()

    request = respx.post("http://localhost:8080/webhook").mock(return_value=httpx.Response(204))
    await connector.dispatch_event("measure")
    assert request.called

@respx.mock
async def test_webhooks() -> None:
    webhook = Webhook(url="http://localhost:8080/webhook", events=["before:measure", "after:adjust"], secret="test")
    config = WebhooksConfiguration(__root__=[webhook])
    connector = WebhooksConnector(config=config)
    await connector.startup()

    request = respx.post("http://localhost:8080/webhook").mock(return_value=httpx.Response(204))
    await connector.dispatch_event("measure")
    assert request.called

    await connector.dispatch_event("adjust")
    assert request.called

async def test_unresponsive_webhook_doesnt_crash() -> None:
    webhook = Webhook(url="http://localhost:8259/webhook", events=["before:measure", "after:adjust"], secret="test")
    config = WebhooksConfiguration(__root__=[webhook])
    connector = WebhooksConnector(config=config)
    await connector.startup()
    await connector.dispatch_event("adjust")

def test_headers_are_added_to_requests() -> None:
    pass

# TODO: Test after:metrics, test schema

@respx.mock
async def test_after_metrics_webhook() -> None:
    webhook = Webhook(url="http://localhost:8080/webhook", events=["after:metrics"], secret="w00t")
    config = WebhooksConfiguration(__root__=[webhook])
    connector = WebhooksConnector(config=config)
    await connector.startup()

    request = respx.post("http://localhost:8080/webhook").respond(204)
    provider = WebhookEventConnector(config=BaseConfiguration())
    provider.__connectors__.append(connector)
    results = await provider.dispatch_event("metrics")

    assert request.called

async def test_after_metrics_content_type() -> None:
    pass
    # Content-Type: application/vnd.opsani.servo.events.after:metrics+json
    # Content-Type: application/vnd.opsani.servo.webhooks+json
    # Content-Type: application/vnd.opsani.servo-webhooks+json
# await asyncio.sleep(2)

# no colon, wrong casing, no such event, mixed collection (number and strings)
def test_bad_event_inputs() -> None:
    pass

def test_root_configuration() -> None:
    pass

def test_event_body() -> None:
    pass

# TODO: Content-Types and shit

def test_request_schema() -> None:
    pass

def test_channels_and_events_cannot_be_empty() -> None:
    with pytest.raises(pydantic.ValidationError, match='missing webhook data source: events and channels cannot both be empty'):
        Webhook(url="http://localhost:8080/webhook", secret="testing")

@respx.mock
async def test_hmac_signature() -> None:
    webhook = Webhook(url="http://localhost:8080/webhook", events="after:measure", secret="testing")
    config = WebhooksConfiguration(__root__=[webhook])
    connector = WebhooksConnector(config=config)
    await connector.startup()

    info = {}
    def match_and_mock(request):
        if request.method != "POST":
            return None

        if "x-servo-signature" in request.headers:
            signature = request.headers["x-servo-signature"]
            body = request.read()
            info.update(dict(signature=signature, body=body))

        return httpx.Response(204)

    webhook_request = respx.route().mock(side_effect=match_and_mock)
    await connector.dispatch_event("measure")
    assert webhook_request.called

    expected_signature = info["signature"]
    signature = str(hmac.new("testing".encode(), info["body"], hashlib.sha1).hexdigest())
    assert signature == expected_signature

def test_cancelling_event_from_before_request() -> None:
    pass

class TestCLI:
    def test_list(self) -> None:
        pass

    def test_schema(self) -> None:
        pass

    def test_trigger(self) -> None:
        pass

    def test_validate(self) -> None:
        pass

# TODO: Test backoff and retry
# TODO: Test generate

def test_generate():
    config = WebhooksConfiguration.generate()
    debug(config.yaml())
    #debug(config.dict(exclude={"webhooks": {'events': {'__all__': {'signature'} }}}))

@pytest.mark.parametrize(
    "event_str,found,resolved",
    [
        ("before:measure", True, "before:measure"),
        ("on:measure", True, "measure"),
        ("measure", True, "measure"),
        ("after:measure", True, "after:measure"),
        ("invalid:adjust", False, None),
        ("before:invalid", False, None),
        ("BEFORE:adjust", False, None),
        ("before:MEASURE", False, None),
        ("", False, None),
        ("nothing", False, None),
    ]
)
def test_from_str(event_str: str, found: bool, resolved: str):
    ec = EventContext.from_str(event_str)
    assert bool(ec) == found
    assert (ec.__str__() if ec else None) == resolved

class FakeAPI(uvicorn.Server):
    """Testing server for implementing API fakes on top of Uvicorn and FastAPI.

    The test server is meant to be paired with pytest fixtures that enable a
    simple mechanism for utilizing API fakes in testing.

    A fake is a protocol compliant stand-in for another system that aids in testing
    by providing stateless, deterministic, and isolated implementations of dependent
    services. Fakes tend to be easier to develop and less brittle than mocking, which
    tends to cut out entire subsystems such as network transport. A fake, in contrast,
    focuses on delivering a request/response compatible stand-in for the real system
    and supports high velocity development and testing by eliminating concerns such as
    stateful persistence, cross talk from other users/developers, and the drag of latency.

    Usage:
        @pytest.fixture
        async def fakeapi_url(fastapi_app: fastapi.FastAPI, unused_tcp_port: int) -> AsyncIterator[str]:
            server = FakeAPI(fastapi_app, port=unused_tcp_port)
            await server.start()
            yield server.base_url
            await server.stop()
    """

    def __init__(self, app: fastapi.FastAPI, host: str = '127.0.0.1', port: int = 8000) -> None:
        """Initialize a FakeAPI instance by mounting a FastAPI app and starting Uvicorn.

        Args:
            app (FastAPI, optional): the FastAPI app.
            host (str, optional): the host ip. Defaults to '127.0.0.1'.
            port (int, optional): the port. Defaults to 8000.
        """
        self._startup_done = asyncio.Event()
        super().__init__(config=uvicorn.Config(app, host=host, port=port))

    async def startup(self, sockets: Optional[List] = None) -> None:
        """Override Uvicorn startup to signal any tasks blocking to await startup."""
        await super().startup(sockets=sockets)
        self._startup_done.set()

    async def start(self) -> None:
        """Start up the server and wait for it to initialize."""
        self._serve_task = asyncio.create_task(self.serve())
        await self._startup_done.wait()

    async def stop(self) -> None:
        """Shut down server asynchronously."""
        self.should_exit = True
        await self._serve_task

    @property
    def base_url(self) -> str:
        """Return the base URL for accessing the FakeAPI server."""
        return f"http://{self.config.host}:{self.config.port}/"

@pytest.fixture
def fastapi_app() -> fastapi.FastAPI:
    """Return a FastAPI instance for testing in the current scope.

    To utilize the FakeAPI fixtures, define a module local FastAPI object
    that implements the API interface that you want to work with and return it
    from an override implementation of the `fastapi_app` fixture.

    The default implementation is abstract and raises a NotImplementedError.

    To interact from the FastAPI app within your tests, invoke the `fakeapi_url`
    fixture to obtain the base URL for a running instance of your fastapi app.
    """
    raise NotImplementedError(f"incomplete fixture implementation: build a FastAPI fixture modeling the system you want to fake")

@pytest.fixture
async def fakeapi_url(fastapi_app: fastapi.FastAPI, unused_tcp_port: int) -> AsyncIterator[str, None]:
    """Run a FakeAPI server as a pytest fixture and yield the base URL for accessing it."""
    server = FakeAPI(app=fastapi_app, port=unused_tcp_port)
    await server.start()
    yield server.base_url
    await server.stop()

@pytest.fixture
async def fakeapi_client(fakeapi_url: str) -> AsyncIterator[httpx.AsyncClient]:
    """Yield an httpx client configured to interact with a FakeAPI server."""
    async with httpx.AsyncClient(
        headers={
            'Content-Type': 'application/json',
        },
        base_url=fakeapi_url,
    ) as client:
        yield client


class Notification(pydantic.BaseModel):
    count: int

notifications: List[Notification] = []

@pytest.fixture(autouse=True)
def _reset_notifications_list() -> None:
    notifications.clear()

api = fastapi.FastAPI()

@api.post("/")
async def create_notification(notification: Notification):
    servo.logger.success(f"Received notification: {notification}")
    notifications.append(notification)
    return notification

@pytest.fixture
def fastapi_app() -> fastapi.FastAPI:
    return api

class PublisherConnector(servo.BaseConnector):
    count: int = 0

    @servo.on_event()
    async def startup(self) -> None:
        @self.publish("the_news", every=1.0)
        async def _publish_count(publisher: servo.pubsub.Publisher) -> None:
            message = servo.pubsub.Message(json={"count": self.count})
            await publisher(message)
            servo.logger.debug(f"Published message {message}")
            self.count += 1

async def test_channel_webhooks(
    fakeapi_url: str,
    fastapi_app: fastapi.FastAPI
) -> None:
    publisher = PublisherConnector(config={})

    webhook = Webhook(url=fakeapi_url, channels=["the_news"], secret="testing")
    config = WebhooksConfiguration(__root__=[webhook])
    connector = WebhooksConnector(config=config, pubsub_exchange=publisher.pubsub_exchange)

    publisher.pubsub_exchange.start()

    await publisher.startup()
    await connector.startup()

    await asyncio.sleep(3.5)

    assert publisher.count
    assert notifications
    assert publisher.count == len(notifications)

class ResponseObserverConnector(servo.BaseConnector):
    messages: List[servo.Message] = []

    @servo.on_event()
    async def startup(self) -> None:
        @self.subscribe("the_responses")
        def _message_received(message: servo.Message, channel: servo.Channel) -> None:
            servo.logger.info(f"Notified of a new Message: {message}, {channel}")
            self.messages.append(message)

async def test_channel_webhooks_with_response_channel(
    fakeapi_url: str,
    fastapi_app: fastapi.FastAPI
) -> None:
    publisher = PublisherConnector(config={})
    response_observer = ResponseObserverConnector(config={}, pubsub_exchange=publisher.pubsub_exchange)

    webhook = Webhook(url=fakeapi_url, channels=["the_news"], response_channel="the_responses", secret="testing")
    config = WebhooksConfiguration(__root__=[webhook])
    connector = WebhooksConnector(config=config, pubsub_exchange=publisher.pubsub_exchange)

    publisher.pubsub_exchange.start()

    await publisher.startup()
    await response_observer.startup()
    await connector.startup()

    await asyncio.sleep(3.5)

    assert publisher.count
    assert notifications
    assert publisher.count == len(notifications)
    assert len(response_observer.messages) == len(notifications)
