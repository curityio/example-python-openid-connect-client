# OpenID Connect Demo
This is a demo application to explain the basic functionality of OpenID Connect. 

## Usage
    python app.py

Flask will start a webserver on localhost that can be used for demo purposes. The webserver will use SSL with a certificate for localhost.
Browse to https://localhost:5443 to see the app.

## Dependencies

**python 2.x** Tested with python 2.7.10

**OpenSSL 1.0** to be able to do modern TLS versions. Python togheter with 0.9.x has a bug that makes it impossible to select protocol in the handshake, so it cannot connect to servers that have disabled SSLv2.

Python dependencies can be installed by using Pip.
	pip install -r requirements.txt


## settings.json
Settings.json is used as a configuration file for the example app. Change the values to match your system.

**redirect_uri**  
string  
mandatory  

The redirect uri to use, must be registered for the client at the OpenID Connect server.

**client_id**  
string  
mandatory

The id for the client. Used to authenticate the client against the authorization server endpoint.

**client_secret**  
string  
mandatory  

The shared secret to use for authentication against the token endpoint.

**discovery_url**  
url  

The url where the metadata of the sever can be found. Should contain information about the endpoints and keys to be used. Configuration from the discovery url will override configuration from settings.json.

**scope**  
string  
default: *openid*  

Scopes to ask for.

**jwks_uri**  
url  

Uri that points to the JWK set. Mandatory if `discovery_url` is not set, and id_token us used

**authorization_endpoint**  
url  

Url to the authorization_endpoint. Mandatory if `discovery_url` is not set.

**token_endpoint**  
url  

Url to the token_endpoint. Mandatory if `discovery_url` is not set.

**issuer**
string

Token issuer. Mandatory if an id_token is used and `discovery_url` is not set.

**verify_ssl_server**  
boolean  
default: *true*  

Set to false to disable certificate checks.

**users**  
string[]  

An array of usernames that the app should be able to impersonate.

**get_userinfo**  
boolean  
default: *false*  

## Questions and Support

For questions and support, contact Curity AB:

> Curity AB
>
> info@curity.io
> https://curity.io


Copyright (C) 2016 Curity AB.
