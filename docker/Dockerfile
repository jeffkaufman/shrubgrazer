FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

EXPOSE 7096
VOLUME /usr/src/app/public
WORKDIR /usr/src/app

# Need Nginx and uWSGI
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        curl \
        nginx \
        python3 \
        python3-requests \
        uwsgi-plugin-python3 \
        && \
        rm -rf /var/lib/apt/lists/* && \
        apt-get clean

RUN update-ca-certificates

# Library
COPY create-client.sh /usr/src/app/create-client.sh
COPY get-user-token.sh /usr/src/app/get-user-token.sh
COPY shrubgrazer.py /usr/src/app/shrubgrazer.py
COPY templates /usr/src/app/templates

# Configuration
COPY users.json /usr/src/app/users.json

CMD ["uwsgi", "--socket", ":7096", \
              "--plugin", "python3", \
              "--enable-threads", \
              "--wsgi-file", "/usr/src/app/shrubgrazer.py", \
              "--protocol", "uwsgi" ]
