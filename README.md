# shrubgrazer

Alternative Mastodon UI, with algorithmic feed and tree-style discussions.

Primarily written as a prototype and demonstration.

See https://www.jefftk.com/p/introducing-shrubgrazer for more details
and screenshots.

## Installation

Create a file `users.json` next to `shrubgrazer.py` with the accounts
of the users you want to support.  Ex:

    $ cat users.json
    ["@jefftk@mastodon.mit.edu"]

This is a python WSGI app, with [no
dependencies](https://www.jefftk.com/p/designing-low-upkeep-software)
outside of the python standard library and whatever you decide to use
to serve it.  If you want to use Nginx with uWSGI, install them both
and then use a configuration like:

```
nginx.conf:
  location /shrubgrazer {
    include uwsgi_params;
    uwsgi_pass 127.0.0.1:7096;
    add_header Cache-Control "private;max-age=0";
  }

/etc/systemd/system/uwsgi-shrubgrazer.service:
  [Unit]
  Description=uWSGI shrubgrazer

  [Service]
  ExecStart=/usr/bin/uwsgi_python3 --socket :7096 --wsgi-file /path/to/shrubgrazer.py
  Restart=always
  KillSignal=SIGQUIT
  Type=notify
  NotifyAccess=all

  [Install]
  WantedBy=multi-user.target

$ sudo systemctl enable uwsgi-shrubgrazer
$ sudo systemctl daemon-reload
```

