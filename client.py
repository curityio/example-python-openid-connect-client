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
            discovery = urllib2.urlopen(self.config['discovery_url'], context=self.ctx)
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

        revoke_request = urllib2.Request(self.config['revocation_endpoint'])
        data = {
            # Assignment 3
            # Add the data to the revocation request
        }
        urllib2.urlopen(revoke_request, urllib.urlencode(data), context=self.ctx)

    def refresh(self, refresh_token):
        """
        Refresh the access token with the refresh_token
        :param refresh_token:
        :return: the new access token
        """
        data = {
            # Assignment 2
            # Add the data to the refresh request
        }
        token_response = urllib2.urlopen(self.config['token_endpoint'], urllib.urlencode(data), context=self.ctx)
        return json.loads(token_response.read())

    def get_authn_req_url(self, session, acr, forceAuthN):
        """
        :param session: the session, will be used to keep the OAuth state
        :return redirect url for the OAuth code flow
        """
        state = tools.generate_random_string()
        session['state'] = state
        request_args = self.__authn_req_args(state)
        if acr: request_args["acr_values"] = acr
        if forceAuthN: request_args["prompt"] = "login"
        login_url = "%s?%s" % (self.config['authorization_endpoint'], urllib.urlencode(request_args))
        print "Redirect to federation service %s" % login_url
        return login_url

    def get_token(self, code):
        """
        :param code: The authorization code to use when getting tokens
        :return the json response containing the tokens
        """

        # Assignment 1
        # Fill in the the missing data for the token request

        data = {'client_id': self.config['client_id'],
                'redirect_uri': self.config['redirect_uri'],
                'grant_type': 'authorization_code'}

        # Exchange code for tokens
        try:
            token_response = urllib2.urlopen(self.config['token_endpoint'], urllib.urlencode(data), context=self.ctx)
        except urllib2.URLError as te:
            print "Could not exchange code for tokens"
            raise te
        return json.loads(token_response.read())

    def __authn_req_args(self, state):
        """
        :param state: state to send to authorization server
        :return a map of arguments to be sent to the authz endpoint
        """
        args = {'scope': self.config['scope'],
                'response_type': 'code',
                'client_id': self.config['client_id'],
                'state': state,
                'redirect_uri': self.config['redirect_uri']}

        if 'authn_parameters' in self.config:
            args.update(self.config['authn_parameters'])
        return args
