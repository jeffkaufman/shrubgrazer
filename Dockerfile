FROM alpine:3.10

EXPOSE 7096
VOLUME /usr/src/app/public
WORKDIR /usr/src/app

# Need Nginx and uWSGI
RUN apk add --no-cache \
        nginx \
        uwsgi-python3 \
        python3 \
        py3-requests

# Library
COPY create-client.sh /usr/src/app/create-client.sh
COPY get-user-token.sh /usr/src/app/get-user-token.sh
COPY shrubgrazer.py /usr/src/app/shrubgrazer.py

# Configuration
COPY users.json /usr/src/app/users.json

CMD ["uwsgi", "--socket", ":7096", \
              "--uid", "uwsgi", \
              "--plugins", "python3", \
              "--wsgi-file", "/usr/src/app/shrubgrazer.py", \
              "--protocol", "uwsgi" ]
