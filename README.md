# shrubgrazer

Alternative Mastodon UI.  Very much in progress.

Current status:
* Displays posts: https://www.jefftk.com/shrubgrazer/post/[id]
* Displays a bare feed for listed users: https://www.jefftk.com/shrubgrazer/

Goals:
* Algorithmic feed: https://www.jefftk.com/p/user-controlled-algorithmic-feeds
* Tree-style display of posts

Algorithmic feed plan:
* Track which entries have been on screen for at least a second
  * "Unviewed" entries are ones that haven't been
* Per-person priority scores
  * Can click on posts to up/down priority, plus there's a control panel
* Feed is a prioritized list of unviewed entries:
  * First sort by user priority
  * Then group by thread
    * This prevents seeing posts in 3/3, 2/3, 1/3 order
  * Then show chronologically
  * For later: give some context for posts
* When viewing a given post's tree, unviewed items are marked in the left margin

Next steps:
* SQLite for storing users, priorities, and views
* Unprioritized feed
* Voting
* Control panel
* View tracking
* Prioritized feed


## Installation

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
  ExecStart=/usr/bin/uwsgi_python3 --socket :7096 --wsgi-file /home/jefftk/code/shrubgrazer/shrubgrazer.py
  Restart=always
  KillSignal=SIGQUIT
  Type=notify
  NotifyAccess=all

  [Install]
  WantedBy=multi-user.target

$ sudo systemctl enable uwsgi-shrubgrazer
$ sudo systemctl daemon-reload
```
