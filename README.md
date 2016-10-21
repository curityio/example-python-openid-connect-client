# OpenID Connect Demo
This is a demo application to explain how the OpenID Connect code flow is implemented.

## Usage

```bash
$ python app.py
```

Flask will start a web server listening on all interfaecs that can be used for demo purposes. The webserver will use HTTPS with a certificate for localhost.
Browse to https://localhost:5443 to see the app.

## Dependencies

**python 2.x** (tested with python 2.7.10)

**OpenSSL 1.0** to be able to do modern TLS versions. Python together with 0.9.x has a bug that makes it impossible to select protocol in the handshake, so it cannot connect to servers that have disabled SSLv2.

Python dependencies can be installed by using PIP: `pip install -r requirements.txt`

## settings.json
Settings.json is used as a configuration file for the example app. Change the values to match your system.

Name            | Type    | Mandatory | Default  | Description
----------------| ------- | :-------: | -------- | :---------------
`redirect_uri`  | string  |    ✓      |          | The redirect uri to use, must be registered for the client at the OpenID Connect server.
`client_id`     | string  |    ✓      |          | The id for the client. Used to authenticate the client against the authorization server endpoint.
`client_secret` | string  |    ✓      |          | The shared secret to use for authentication against the token endpoint.
`discovery_url` | URL     |    ✓      |          | The URL where the metadata of the sever can be found. Should contain information about the endpoints and keys to be used. Configuration from the discovery url will override configuration from settings.json.
`scope`         | string  |           | `openid` | The scopes to ask for.
`jwks_uri`      | URL     | if `discovery_url` is not set and the `openid` scope is requested          |          | The URL that points to the JWK set.
`authorization_endpoint` | URL | if `discovery_url` is not set     |          | The URL to the authorization_endpoint.
`token_endpoint`| URL     |           |          | The URL to the token_endpoint. Mandatory if `discovery_url` is not set.
`issuer`        | string  | if the `openid` scope is requested and `discovery_url` is not set          |          | The ID of the token issuer.
`verify_ssl_server` | boolean |       | `true`   | Set to false to disable certificate checks.
`debug`         | boolean |           | `false`  | If set to true, Flask will be in debug mode and write stacktraces if an error occurs
`port`          | number  |           | `5443`   | The port that the Flask server should listen to
`disable_https` | boolean |           | `false`  | Set to true to run on http
`base_url`      | string  |           |          | base url to be added to internal redirects. Set this to enable the client to be behind a proxy.

## Questions and Support

For questions and support, contact Curity AB:

> Curity AB
>
> info@curity.io
> https://curity.io


Copyright (C) 2016 Curity AB.
