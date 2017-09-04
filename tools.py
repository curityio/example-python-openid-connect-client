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

import base64
import random
import string
import ssl


def base64_urldecode(s):
    ascii_string = str(s)
    ascii_string += '=' * (4 - (len(ascii_string) % 4))
    return base64.urlsafe_b64decode(ascii_string)


def decode_token(token):
    """
    Decode a jwt into readable format.

    :param token:
    :return: A decoded jwt, or None if its not a JWT
    """
    parts = token.split('.')

    if token and len(parts) == 3:
        return base64_urldecode(parts[0]), base64_urldecode(parts[1])

    # It's not a JWT
    return None


def generate_random_string():
    """
    :return: a 20 character random stringmusing only ascii characters and digits
    """
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))


def get_ssl_context(config):
    """
    :return a ssl context with verify and hostnames settings
    """
    ctx = ssl.create_default_context()

    if 'verify_ssl_server' in config and config['verify_ssl_server'].lower() == 'false':
        print 'Not verifying ssl certificates'
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

