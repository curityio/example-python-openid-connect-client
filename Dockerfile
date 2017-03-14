#
# Copyright (C) 2016 Curity AB. All rights reserved.
#
# The contents of this file are the property of Curity AB.
# You may not copy or use this file, in either source code
# or executable form, except in compliance with terms
# set by Curity AB.
#
# For further information, please contact Curity AB.
#

FROM python:2.7
MAINTAINER Curity AB

ADD requirements.txt /usr/src/
RUN pip install --no-cache-dir -r /usr/src/requirements.txt
WORKDIR /oidc-example
EXPOSE 5443


RUN mkdir -p /oidc-example
ADD keys /oidc-example/keys
ADD static /oidc-example/static
ADD templates /oidc-example/templates
ADD settings.json /oidc-example/settings.json
ADD *.py /oidc-example/

CMD ["python", "app.py"]
