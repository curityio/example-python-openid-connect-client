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


def base64_urldecode(string):
    string.replace('-', '+')
    string.replace('_', '/')
    string += '=' * (4 - (len(string) % 4))
    return base64.b64decode(string)


def decode_token(token):
    """
    Decode a jwt into readable format.

    :param token:
    :return: A decoded jwt, or None if its not a JWT
    """
    if token and len(token.split('.')) == 3:
        header = token.split('.')[0]
        header += '=' * (4 - len(header) % 4)

        payload = token.split('.')[1]
        payload += '=' * (4 - len(payload) % 4)

        return base64.b64decode(header), base64.b64decode(payload)

    # It's not a JWT
    return None


def generate_random_string():
    """
    :return: a 20 character random stringmusing only ascii characters and digits
    """
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
