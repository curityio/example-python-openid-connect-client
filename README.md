# OpenID Connect Demo
This is a demo application to explain how the OpenID Connect code flow is implemented.

## Usage

```bash
$ python app.py
```

Flask will start a web server listening on all interfaces that can be used for demo purposes. The webserver will use HTTPS with a certificate for localhost.
Browse to https://localhost:5443 to see the app.

## Dependencies

**python 2.x** (tested with python 2.7.10)

**OpenSSL 1.0** to be able to do modern TLS versions. Python together with 0.9.x has a bug that makes it impossible to select protocol in the handshake, so it cannot connect to servers that have disabled SSLv2.

Python dependencies can be installed by using PIP: `pip install -r requirements.txt`

## settings.json
Settings.json is used as a configuration file for the example app. Change the values to match your system.

Name                | Type    | Default  | Description
--------------------| ------- | -------- | :---------------
`issuer`            | string  |          | The ID of the token issuer. This is used for both OpenID Connect Discovery, and validating a ID Token. Mandatory for discovery
`client_id`         | string  |          | The ID for the client. Used to authenticate the client against the authorization server endpoint.
`client_secret`     | string  |          | The shared secret to use for authentication against the token endpoint.
`dcr_client_id`     | string  |          | The client ID of the client for to use for registration.
`dcr_client_secret` | string  |          | The client secret of the client for to use for registration.
`scope`             | string  | `openid` | The scopes to ask for.
`verify_ssl_server` | boolean | `true`   | Set to false to disable certificate checks.
`debug`             | boolean | `false`  | If set to true, Flask will be in debug mode and write stacktraces if an error occurs. Some extra logging is also printed.
`port`              | number  | `5443`   | The port that the Flask server should listen to
`disable_https`     | boolean | `false`  | Set to true to run on http
`logout_endpoint`   | string  |          | The URL to the logout endpoint at the authentication service. If set, the user will be redirected here after a logout has been made in the application. 
`base_url`          | string  |          | base url to be added to internal redirects. If this is not configured, the base url will be extracted from the first request to the index page

### Mandatory parameters if discovery is not available
Name                     | Type |  Description
-------------------------|------|-------------
`jwks_uri`               | URL  |  The URL that points to the JWK set. Mandatory if the openid scope is requested.
`authorization_endpoint` |      |  The URL to the authorization endpoint.
`token_endpoint`         | URL  |  The URL to the token endpoint.
`registration_endpoint`  | URL  |  The URL to the registration endpoint.

## Docker
To run the example in a Docker container, build an image and run a container like this.:

```bash
$ docker build -t curityio/openid-python-example
$ docker run -ti curityio/openid-python-example

```
All setting can be set using an environment variable with uppercase letters. Example:
```bash
$ docker build -t curityio/openid-python-example
$ docker run -e DEBUG=true -e ISSUER=se.curity -ti curityio/openid-python-example
```
## Docker Compose
In the root of the repository, there is a `docker-compose.yml`. Customize the settings using environment variables with uppercase letters.

```bash
$ docker-compose up
```

## Questions and Support

For questions and support, contact Curity AB:

> Curity AB
>
> info@curity.io
> https://curity.io


Copyright (C) 2016 Curity AB.
