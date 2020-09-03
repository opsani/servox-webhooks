# CHANGELOG

servo-webhooks is a connector for [Opsani Servo](https://github.com/opsani/servox) that
provides a flexible webhooks emitter based on servo events.

servo-webhooks is distributed under the terms of the Apache 2.0 license. 

This changelog catalogs all notable changes made to the project. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Releases are 
versioned in accordance with [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2020-09-03

### Changed:
- Removed direct dependency on `httpx` in favor of `servo` dependency.

## [0.2.0] - 2020-08-30

### Changed
- Updated servox target dependency to v0.6.0

## [0.1.0] - 2020-08-23

Initial public release.

This connector was incubated within the mainline servox repository and shipped as part of
servox v0.5.0. Much of the core functionality is implemented but there are outstanding TODO
items. In particular, cancellation behaviors are currently unimplemented as are the CLI tasks 
described in the README. Documentation around the specifics of the request payloads also
deserve expansion.

### Added
- Emit webhooks before and after an event is handled by the servo.
- Include an HMAC digest based signature for verifying webhook request authenticity and integrity.
- Support for backoff and retry of webhook requests on failure.
