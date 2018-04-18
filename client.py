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
import hashlib

import json
import urllib
import urllib2

import tools


class Client:
    def __init__(self, config):
        self.config = config

        print 'Getting ssl context for oauth server'
        self.ctx = tools.get_ssl_context(self.config)
        self.__init_config()


    def __init_config(self):
        if 'discovery_url' in self.config:
            discovery = self.urlopen(self.config['discovery_url'], context=self.ctx)
            self.config.update(json.loads(discovery.read()))
        else:
            print "No discovery url configured, all endpoints needs to be configured manually"


        # Mandatory settings
        if 'authorization_endpoint' not in self.config:
            raise Exception('authorization_endpoint not set.')
        if 'token_endpoint' not in self.config:
            raise Exception('token_endpoint not set.')
        if 'client_id' not in self.config:
            raise Exception('client_id not set.')
        if 'client_secret' not in self.config:
            raise Exception('client_secret not set.')
        if 'redirect_uri' not in self.config:
            raise Exception('redirect_uri not set.')

        if 'scope' not in self.config:
            self.config['scope'] = 'openid'

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

    def get_authn_req_url(self, session, acr, forceAuthN, scope):
        """
        :param session: the session, will be used to keep the OAuth state
        :return redirect url for the OAuth code flow
        """
        state = tools.generate_random_string()
        session['state'] = state
        session['code_verifier'] = code_verifier = tools.generate_random_string(100)

        code_challenge = tools.base64_urlencode(hashlib.sha256(code_verifier).digest())

        request_args = self.__authn_req_args(state, scope, code_challenge, "S256")
        if acr: request_args["acr_values"] = acr
        if forceAuthN: request_args["prompt"] = "login"
        delimiter = "?" if self.config['authorization_endpoint'].contains("?") else "&"
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
