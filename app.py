##########################################################################
# Copyright 2016 Curity AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

import json
import sys
import urllib2
from flask import redirect, request, render_template, session, Flask
from jwkest import BadSignature
from urlparse import urlparse

from client import Client
from tools import decode_token, generate_random_string
from validator import JwtValidator
from config import Config

_app = Flask(__name__)


class UserSession:
    def __init__(self):
        pass

    access_token = None
    refresh_token = None
    id_token = None
    access_token_json = None
    id_token_json = None
    name = None
    api_response = None


@_app.route('/')
def index():
    """
    :return: the index page with the tokens, if set.
    """
    user = None
    is_logged_in = False
    if 'session_id' in session:
        user = _session_store.get(session['session_id'])
    if user:
        is_logged_in = True
        if user.id_token:
            user.id_token_json = decode_token(user.id_token)
        if user.access_token:
            user.access_token_json = decode_token(user.access_token)

    if is_logged_in:
        return render_template('index.html',
                            server_name=urlparse(_config['authorization_endpoint']).netloc,
                            session=user)
    else:
        return render_template('welcome.html')


@_app.route('/start-login')
def start_code_flow():
    """
    :return: redirects to the authorization server with the appropriate parameters set.
    """
    login_url = _client.get_authn_req_url(session, request.args.get("acr", None), request.args.get("forceAuthN", False))
    return redirect(login_url)


@_app.route('/logout')
def logout():
    """
    Logout clears the session, along with the tokens
    :return: redirects to /
    """
    if 'session_id' in session:
        del _session_store[session['session_id']]
    session.clear()
    if 'logout_endpoint' in _config:
        print "Logging out against", _config['logout_endpoint']
        return redirect(_config['logout_endpoint'] + '?redirect_uri=' + _base_url)
    return redirect_with_baseurl('/')


@_app.route('/refresh')
def refresh():
    """
    Refreshes the access token using the refresh token
    :return: redirects to /
    """
    user = _session_store.get(session['session_id'])
    try:
        token_data = _client.refresh(user.refresh_token)
    except Exception as e:
        create_error('Could not refresh Access Token', e)
        return
    user.access_token = token_data['access_token']
    user.refresh_token = token_data['refresh_token']
    return redirect_with_baseurl('/')


@_app.route('/revoke')
def revoke():
    """
    Revokes the access and refresh token and clears the sessions
    :return: redirects to /
    """
    if 'session_id' in session:
        user = _session_store.get(session['session_id'])
        if not user:
            redirect_with_baseurl('/')

        if user.refresh_token:
            try:
                _client.revoke(user.refresh_token)
            except urllib2.URLError as e:
                return create_error('Could not revoke refresh token', e)
            user.refresh_token = None

    return redirect_with_baseurl('/')


@_app.route('/call-api')
def call_api():
    """
    Call an api using the Access Token
    :return: the index template with the data from the api in the parameter 'data'
    """
    if 'session_id' in session:
        user = _session_store.get(session['session_id'])
        if not user:
            return redirect_with_baseurl('/')
        if 'api_endpoint' in _config:
            user.api_response = None
            if user.access_token:
                try:
                    request = urllib2.Request(_config['api_endpoint'])

                    # Assignment 4
                    # Add the access token to the request

                    request.add_header("Accept", 'application/json')
                    response = urllib2.urlopen(request)
                    user.api_response = {'code': response.code, 'data': response.read()}
                except urllib2.HTTPError as e:
                    user.api_response = {'code': e.code, 'data': e.read()}
                except Exception as e:
                    user.api_response = {"code": "unknown error", "data": e.message }
            else:
                user.api_response = None
                print 'No access token in session'
        else:
            user.api_response = None
            print 'No API endpoint configured'

    return redirect_with_baseurl('/')


@_app.route('/callback')
def oauth_callback():
    """
    Called when the resource owner is returning from the authorization server
    :return:redirect to / with user info stored in the session.
    """
    if 'state' not in session or session['state'] != request.args['state']:
        return create_error('Missing or invalid state')

    if 'code' not in request.args:
        return create_error('No code in response')

    try:
        token_data = _client.get_token(request.args['code'])
    except Exception as e:
        return create_error('Could not fetch token(s)', e)
    session.pop('state', None)

    # Store in basic server session, since flask session use cookie for storage
    user = UserSession()

    if 'access_token' in token_data:
        user.access_token = token_data['access_token']

    if _jwt_validator and 'id_token' in token_data:
        # validate JWS; signature, aud and iss.
        # Token type, access token, ref-token and JWT
        if 'issuer' not in _config:
            return create_error('Could not validate token: no issuer configured')

        try:

            # Assignment 5
            # validate JWS; signature, aud and iss.

        except BadSignature as bs:
            return create_error('Could not validate token: %s' % bs.message)
        except Exception as ve:
            return create_error("Unexpected exception: %s" % ve.message)

        user.id_token = token_data['id_token']

    if 'refresh_token' in token_data:
        user.refresh_token = token_data['refresh_token']

    session['session_id'] = generate_random_string()
    _session_store[session['session_id']] = user

    return redirect_with_baseurl('/')


def create_error(message, exception = None):
    """
    Print the error and output it to the page
    :param message:
    :return: redirects to index.html with the error message
    """
    print 'Caught error!'
    print message, exception
    if _app:
        user = None
        if 'session_id' in session:
            user = _session_store.get(session['session_id'])
        return render_template('index.html',
                               server_name=urlparse(_config['authorization_endpoint']).netloc,
                               session=user,
                               error=message)


def load_config():
    """
    Load config from the file given by argument, or settings.json
    :return:
    """
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = 'settings.json'
    config = Config(filename)

    return config.load_config()


def redirect_with_baseurl(path):
    return redirect(_base_url + path)


if __name__ == '__main__':
    # load the config
    _config = load_config()

    _client = Client(_config)

    # load the jwk set.
    if 'jwks_uri' in _config:
        _jwt_validator = JwtValidator(_config)
    else:
        print 'Found no url to JWK set, will not be able to validate JWT signature.'
        _jwt_validator = None

    # create a session store
    _session_store = {}

    # initiate the app
    _app.secret_key = generate_random_string()

    # some default values
    _debug = 'debug' in _config and _config['debug']
    if 'port' in _config:
        _port = _config['port']
    else:
        _port = 5443
    _disable_https = 'disable_https' in _config and _config['disable_https']
    if 'base_url' in _config:
        _base_url = _config['base_url']
    else:
        _base_url = ''

    if _disable_https:
        _app.run('0.0.0.0', debug=_debug, port=_port)
    else:
        _app.run('0.0.0.0', debug=_debug, port=_port, ssl_context=('keys/localhost.pem', 'keys/localhost.pem'))
