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
import os
import urllib
import urllib2

import tools

REGISTEREDclient_FILENAME = 'registered_client.json'

class Client:
    def __init__(self, config):
        self.config = config

        print 'Getting ssl context for oauth server'
        self.ctx = tools.get_ssl_context(self.config)
        self.__init_config()
        self.client_data = None

    def __init_config(self):

        if 'issuer' in self.config:
            meta_data_url = self.config['issuer'] + '/.well-known/openid-configuration'
            print 'Fetching config from: %s' % meta_data_url
            meta_data = urllib2.urlopen(meta_data_url)
            if meta_data:
                self.config.update(json.load(meta_data))
            else:
                print 'Unexpected response on discovery document: %s' % meta_data
        else:
            print 'Found no issuer in config, can not perform discovery. All endpoint config needs to be set manually'

        # Mandatory settings
        if 'authorization_endpoint' not in self.config:
            raise Exception('authorization_endpoint not set.')
        if 'token_endpoint' not in self.config:
            raise Exception('token_endpoint not set.')

        self.read_credentials_from_file()
        if 'client_id' not in self.config:
            print 'Client is not registered.'

        if 'scope' not in self.config:
            self.config['scope'] = 'openid'

    def read_credentials_from_file(self):
        if not os.path.isfile(REGISTEREDclient_FILENAME):
            print 'Client is not registered'
            return

        try:
            registered_client = json.loads(open(REGISTEREDclient_FILENAME).read())
        except Exception as e:
            print 'Could not read credentials from file', e
            return
        self.config['client_id'] = registered_client['client_id']
        self.config['client_secret'] = registered_client['client_secret']
        self.config['redirect_uri'] = registered_client['redirect_uris'][0]
        self.client_data = registered_client

    def register(self):
        """
        Revoke the token
        :raises: raises error when http call fails
        """
        if 'registration_endpoint' not in self.config:
            print 'Authorization server does not support Dynamic Client Registration. Please configure client credentials manually '
            return

        if 'client_id' in self.config:
            raise Exception('Client is already registered')

        print 'Registering client at %s with redirect_uri %s' % (self.config['base_url'], self.config['redirect_uri'])

        register_request = urllib2.Request(self.config['registration_endpoint'])
        data = {
            'redirect_uris': [self.config['redirect_uri']]
        }
        register_response = urllib2.urlopen(register_request, json.dumps(data), context=self.ctx)
        self.client_data = json.loads(register_response.read())

        with open(REGISTEREDclient_FILENAME, 'w') as outfile:
            outfile.write(json.dumps(self.client_data))

        if self.config['debug']:
            tools.print_json(self.client_data)

        self.read_credentials_from_file()

    def revoke(self, token):
        """
        Revoke the token
        :param token: the token to revoke
        :raises: raises error when http call fails
        """
        if 'revocation_endpoint' not in self.config:
            print 'No revocation endpoint set'
            return

        data = {
            'token': token,
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret']
        }
        self.urlopen(self.config['revocation_endpoint'], urllib.urlencode(data), context=self.ctx)

    def refresh(self, refresh_token):
        """
        Refresh the access token with the refresh_token
        :param refresh_token:
        :return: the new access token
        """
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret']
        }
        token_response = self.urlopen(self.config['token_endpoint'], urllib.urlencode(data), context=self.ctx)
        return json.loads(token_response.read())

    def get_authn_req_url(self, session, acr, forceAuthN, scope, forceConsent, allowConsentOptionDeselection):
        """
        :param session: the session, will be used to keep the OAuth state
        :param acr: The acr to request
        :param force_authn: Force the resource owner to authenticate even though a session exist
        :return redirect url for the OAuth code flow
        """
        state = tools.generate_random_string()
        session['state'] = state
        session['code_verifier'] = code_verifier = tools.generate_random_string(100)

        code_challenge = tools.base64_urlencode(hashlib.sha256(code_verifier).digest())

        request_args = self.__authn_req_args(state, scope, code_challenge, "S256")
        if acr: request_args["acr_values"] = acr
        if forceAuthN: request_args["prompt"] = "login"

        if forceConsent:
            if allowConsentOptionDeselection:
                request_args["prompt"] = request_args.get("prompt", "") + " consent consent_allow_deselection"
            else:
                request_args["prompt"] = request_args.get("prompt", "") + " consent"

        delimiter = "?" if self.config['authorization_endpoint'].find("?") < 0 else "&"
        login_url = "%s%s%s" % (self.config['authorization_endpoint'], delimiter, urllib.urlencode(request_args))
        print "Redirect to federation service %s" % login_url
        return login_url

    def get_token(self, code, code_verifier):
        """
        :param code: The authorization code to use when getting tokens
        :return the json response containing the tokens
        """
        data = {'client_id': self.config['client_id'], "client_secret": self.config['client_secret'],
                'code': code,
                "code_verifier": code_verifier,
                'redirect_uri': self.config['redirect_uri'],
                'grant_type': 'authorization_code'}

        # Exchange code for tokens
        try:
            token_response = self.urlopen(self.config['token_endpoint'], urllib.urlencode(data), context=self.ctx)
        except urllib2.URLError as te:
            print "Could not exchange code for tokens"
            raise te
        return json.loads(token_response.read())

    def urlopen(self, url, data=None, context=None):
        """
        Open a connection to the specified url. Sets valid requests headers.
        :param url: url to open - cannot be a request object 
        :data: data to send, optional
        :context: ssl context
        :return the request response
        """
        headers = {
            'User-Agent': 'CurityExample/1.0',
            'Accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
        }
        
        request = urllib2.Request(url, data, headers)
        return urllib2.urlopen(request, context=context)


    def __authn_req_args(self, state, scope, code_challenge, code_challenge_method="plain"):
        """
        :param state: state to send to authorization server
        :return a map of arguments to be sent to the authz endpoint
        """
        if 'client_id' not in self.config:
            raise Exception('Client is not registered')

        args = {'scope': scope,
                'response_type': 'code',
                'client_id': self.config['client_id'],
                'state': state,
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method,
                'redirect_uri': self.config['redirect_uri']}

        if 'authn_parameters' in self.config:
            args.update(self.config['authn_parameters'])
        return args


    def get_client_data(self):
        if not self.client_data:
            self.read_credentials_from_file()

        if self.client_data:
            masked = self.client_data
            masked['client_secret'] = '***********************************'
            return json.dumps(masked)
