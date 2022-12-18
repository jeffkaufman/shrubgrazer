#!/usr/bin/env python3

import os
import re
import json
import html
import time
import string
import urllib
import sqlite3
import secrets
import requests
import traceback
import subprocess
import http.cookies
import dateutil.parser

SCRIPT_DIR = os.path.dirname(__file__)


DB_FILENAME = "%s/sg.db" % SCRIPT_DIR

def initialize_db(cur):
  cur.execute("create table accts("
              " acct text primary key not null,"
              " csrf text unique not null)")
  cur.execute("create table acct_weights("
              " acct text not null,"
              " follow text not null,"
              " weight real not null, "
              " primary key (acct, follow))")
  cur.execute("create table posts("
              " post_id integer primary key not null,"
              " created_at integer not null,"
              " acct text not null,"
              " post_acct text not null)")
  cur.execute("create table views("
              " acct text not null,"
              " post_id integer not null,"
              " ts integer not null,"
              " primary key (acct, post_id, ts))")
  cur.execute("create index idx_views on views (acct, post_id)")

def hasall(d, *vals):
  for val in vals:
    if not d.get(val, None):
      return False
  return True

def removeprefix(s, prefix):
  if s.startswith(prefix):
    return s[len(prefix):]
  return s

def removesuffix(s, suffix):
  if s.endswith(suffix):
    return s[:-len(suffix)]
  return s

def get_display_names(entry_json):
  display_name = entry_json['account']['display_name']
  acct = entry_json['account']['acct']
  if not display_name:
    display_name = acct

  # remove unrecognized emoji colon codes
  display_name = re.sub(":.*:", "", display_name)

  return display_name, acct

def hide_elements(*selectors):
  return "<style>%s{display:none}</style>" % ", ".join(selectors)

def epoch(timestring):
  return int(dateutil.parser.parse(timestring).timestamp())

class FetchError(Exception):
  def __init__(self, response, url):
    self.response = response
    self.url = url
    self.message = "Status %s for %s" % (response.status_code, url)
    super().__init__(self.message)

def fetch(domain, path, access_token=None,
          raw=False, post=False, data=None, headers={}):

  if access_token:
    headers["Authorization"] = "Bearer %s" % access_token

  url = "https://%s/%s" % (domain, path)
  if post:
    response = requests.post(url, headers=headers, data=data)
  else:
    response = requests.get(url, headers=headers)

  if response.status_code != 200:
    raise FetchError(response, url)

  if raw:
    return response

  return response.json()

def redirect(url):
  return template("redirect", url=url)

def set_cookie(k, v, strict=True):
  return [
    ("set-cookie",
     "%s=%s; Secure; HttpOnly; SameSite=%s; Max-Age=%s" % (
       k, v, "Strict" if strict else "Lax", 365*24*60*60))]

def delete_cookies(*cookies):
  return [delete_cookie(cookie) for cookie in cookies]

def delete_cookie(cookie):
  return (
    "set-cookie",
    "%s=deleted; Secure; HttpOnly; SameSite=Strict; Max-Age=0" % cookie)




def create_client(domain, redirect_url):
  website = re.sub("/auth2$", "/", redirect_url)
  subprocess.check_call(["%s/create-client.sh" % SCRIPT_DIR,
                         domain,
                         redirect_url,
                         website,
                         client_config_fname(domain)])

def client_config_fname(domain):
  return "%s/%s.client-config.json" % (SCRIPT_DIR, domain)

def user_allowed(acct):
  with open("%s/users.json" % SCRIPT_DIR) as inf:
    allowed_users = json.load(inf)

  return acct in allowed_users




class Response:
  def __init__(self,
               output="",
               headers=[],
               content_type=None,
               status="200 OK"):
    self.output = output
    self.headers = headers
    self.status = status

    if content_type:
      self.content_type = content_type
    else:
      if status == "200 OK":
        self.content_type = "text/html"
      else:
        self.content_type = "text/plain"

class Request:
  def __init__(self, environ):
    self.cookies = http.cookies.BaseCookie(environ.get('HTTP_COOKIE', ''))
    self.host = environ["HTTP_HOST"]
    self._query = urllib.parse.parse_qs(environ['QUERY_STRING'])
    self.path = environ["PATH_INFO"]

    basepath, self.page = self.path.rsplit("/", 1)
    self.website = "https://%s%s/" % (self.host, basepath)

    self.environ = environ

    # memoized on first use
    self._db = None # cursor, connection
    self._acct = None # @user@domain
    self._form_vals = None

  def make_path(self, new_path):
    return "%s%s" % (self.website, new_path)

  def logged_in(self):
    return 'shrubgrazer-access-token' in self.cookies

  def db(self):
    if not self._db:
      initialize = not os.path.exists(DB_FILENAME)
      con = sqlite3.connect(DB_FILENAME)
      cur = con.cursor()

      if initialize:
        initialize_db(cur)

      self._db = cur, con

    return self._db

  def csrf(self):
    if 'shrubgrazer-csrf-token' not in self.cookies: return ''
    return self.cookies['shrubgrazer-csrf-token'].value

  def access_token(self):
    if 'shrubgrazer-access-token' not in self.cookies: return ''
    return self.cookies['shrubgrazer-access-token'].value

  def acct(self):
    if not self._acct:
      cur, con = self.db()
      cur.execute("select acct from accts where csrf=?", (self.csrf(), ))
      validated_acct, = cur.fetchone()

      if validated_acct != self.cookies['shrubgrazer-acct'].value:
        raise Exception("invalid account")

      self._acct = validated_acct

    return self._acct

  def domain(self):
    _, _, domain = self.acct().split("@")
    return domain

  def form_vals(self):
    if self._form_vals is None:
      request_body_size = int(self.environ.get('CONTENT_LENGTH', 0) or 0)
      self._form_vals = urllib.parse.parse_qs(
        self.environ['wsgi.input'].read(request_body_size))
    return self._form_vals

  def query(self, key):
    if key not in self._query:
      return ''
    return self._query[key][0]


class Card:
  def __init__(self, card_json):
    self.json = card_json

  def render(self):
    if hasall(self.json, 'image'):
      if 'description' not in self.json:
        self.json['description'] = ''

      if 'url' in self.json:
        t = "partial_image_link_card"
      else:
        t = "partial_image_card"

    elif hasall(self.json, 'url', 'title', 'description'):
      t = "partial_link_card"

    else:
      return None

    return template(t, self.json)

class Attachment:
  def __init__(self, attachment_json):
    self.json = attachment_json

  def render(self):
    if self.json['type'] == 'image':
      self.json['image'] = self.json['preview_url']
      return template('partial_image_link_card', self.json)

    return None

class Entry:
  def __init__(self, entry_json, weight=""):
    if entry_json.get('error', None):
      raise Exception(entry_json['error'])
    self.created_at = epoch(entry_json['created_at'])

    self.display_name, self.acct = get_display_names(entry_json)
    self.display_acct = self.acct if self.acct != self.display_name else ""

    self.post_id = entry_json["id"]
    self.weight = weight
    self.external_url = entry_json["url"]
    self.flavor = 'standard'
    self.raw_ts = entry_json['created_at'].split("T")[0]
    self.raw_body = entry_json['content']
    self.children = []
    self.attachments = []
    self.favourited = entry_json.get('favourited', None)

    if hasall(entry_json, 'card'):
      self.attachments.append(Card(entry_json['card']))

    for media_attachment in entry_json.get('media_attachments', []):
      self.attachments.append(Attachment(media_attachment))

  def _load_weight(self, req):
    if self.weight == "":
      cur, con = req.db()
      cur.execute("select aw.weight"
                  " from acct_weights aw"
                  " where aw.acct = ?"
                  "   and aw.follow = ?", (
                    req.acct(), self.acct))
      response = cur.fetchone()
      if response:
        weight, = response
      else:
        weight = 1
      return int(weight)

  def render(self, req, depth=0):
    subs = dict(
      (k, getattr(self, k))
      for k in dir(self)
      if not k.startswith('__'))

    weight = self.weight
    if weight == "" and req.logged_in():
      weight = self._load_weight(req)

    subs['parity'] = str(depth % 2)
    subs['raw_children'] = [
      child.render(req, depth=depth+1)
      for child in self.children]

    subs['raw_attachments'] = [
      attachment.render() for attachment in self.attachments]
    subs['view_url'] = req.make_path("post/%s" % self.post_id)
    subs['favorite_url'] = req.make_path("favorite?post_id=%s&csrf=%s" % (
      self.post_id, req.csrf()))

    subs['raw_adjust_weight'] = template('partial_adjust_weight', subs={
      'up_url': req.make_path(
        "upvote?csrf=%s&follow_id=%s" % (req.csrf(), self.acct)),
      'down_url': req.make_path(
        "downvote?csrf=%s&follow_id=%s" % (req.csrf(), self.acct)),
      'weight': weight,
    })

    subs['raw_favorite_star'] = {
      True: '&#9733;',
      False: '&#9734;',
      None: '',
    }[self.favourited]

    subs['reply_url'] = req.make_path("reply?parent_id=%s&depth=%s&csrf=%s" % (
      self.post_id, depth+1, req.csrf()))

    return template("partial_post", subs)


TEMPLATES = {}

def template(template_name, subs={}, **kwargs):
  if template_name not in TEMPLATES:
    with open("%s/templates/%s.html" % (SCRIPT_DIR, template_name)) as inf:
      t = inf.read()
    TEMPLATES[template_name] = string.Template(t)

  safe_subs = {}
  for k, v in {**subs, **kwargs}.items():
    if type(v) == type([]):
      v = "\n".join([x for x in v if type(x) == type("")])

    if v is None:
      v = ''
    elif type(v) == type(1):
      v = str(v)
    elif type(v) == type(1.0):
      v = "%.1f" % v

    if type(v) != type(""):
      continue

    if not k.startswith("raw_"):
      v = html.escape(v)
    safe_subs[k] = v

  try:
    return TEMPLATES[template_name].substitute(safe_subs)
  except Exception:
    with open("%s/details.txt" % SCRIPT_DIR, "w") as outf:
      outf.write(json.dumps(safe_subs))
    raise


def post(post_id, req):
  if not re.match('^[0-9]+$', post_id):
    return "invalid post id\n"

  if req.logged_in():
    domain = req.domain()
  else:
    domain = "mastodon.mit.edu"

  body = fetch(domain, "api/v1/statuses/%s" % post_id, req.access_token())
  context = fetch(domain, "api/v1/statuses/%s/context" % post_id,
                  req.access_token())

  rendered_ancestors = [
    Entry(ancestor).render(req)
    for ancestor in context["ancestors"]]

  root = Entry(body)
  root.flavor = 'root'
  children_by_id = {post_id: root}

  for child_json in context["descendants"]:
    child = Entry(child_json)

    children_by_id[child_json["id"]] = child
    children_by_id[child_json["in_reply_to_id"]].children.append(child)

  hidden = ""

  if not req.logged_in():
    hidden += hide_elements(".loggedin")

  subs = {
    'raw_css': template('css') + hidden,
    'raw_header': template(
      'partial_header',
      website=req.website,
      csrf=req.csrf()),
    'raw_ancestors': rendered_ancestors,
    'raw_post': root.render(req),
    'acct': req.acct() if req.logged_in() else '',
    'raw_view_tracker_script': template(
      'view_tracker_script',
      raw_vote_script=template('vote_script'),
      csrf=req.csrf(),
      more_content_url='',
      should_track_views="true" if req.logged_in() else "false",
      populate_feed_url='',
      view_ping_url=req.make_path("view_ping")),
  }

  return Response(template("post", subs))

ONE_HOUR_S=60*60

def prepare_history(req, max_ts=None):
  if max_ts is None:
    max_ts = int(time.time())
  cur, con = req.db()
  cur.execute("select post_id, ts from views "
              "where acct=? and ts<? "
              "order by ts desc "
              "limit 10", (req.acct(), max_ts))
  result = cur.fetchall()
  post_ids = [x[0] for x in result]
  if post_ids:
    _, new_max_ts = result[-1]
  else:
    new_max_ts = "END";

  # We'll get the weights later.
  weighted_posts = [(post_id, "") for post_id in post_ids]
  return render_weighted_posts(req, weighted_posts), new_max_ts

def more_history_json(req):
  rendered_entries, new_max_ts = prepare_history(
    req, max_ts=int(req.query("next")))

  return Response(json.dumps({
    "rendered_entries": rendered_entries,
    "next_token": new_max_ts,
  }), content_type="application/json")

def populate_feed_json(req):
  next_token = req.query('next')
  cur, con = req.db()

  feed_population_state = None

  if not next_token:
    cur.execute("select max(post_id) from posts where acct = ?", (req.acct(), ))
    response = cur.fetchone()
    if response:
      next_token = "&min_id=%s" % response
    else:
      next_token = ""  # never seen this user before

  path = "api/v1/timelines/home?limit=40%s" % next_token
  response = fetch(req.domain(), path, req.access_token(), raw=True)
  acct = req.acct()

  for entry in response.json():
    while hasall(entry, "reblog"):
      entry = entry["reblog"]

    cur.execute("insert or ignore into posts "
                "(post_id, created_at, acct, post_acct) "
                "values (?, ?, ?, ?)",
                (entry["id"],
                 epoch(entry["created_at"]),
                 acct,
                 entry["account"]["acct"]))
  con.commit()

  if "min_id" in next_token:
    prev_url = response.links.get('prev',{}).get('url','')
    if prev_url:
      feed_population_state, = re.findall("(&min_id=[0-9]+)$", prev_url)
  elif "max_id" in next_token:
    next_url = response.links.get('next',{}).get('url','')
    if next_url:
      feed_population_state, = re.findall("(&max_id=[0-9]+)$", next_url)

  return Response(json.dumps({
    "feed_population_state": feed_population_state,
  }), content_type="application/json")

def seen_id(cur, post_id):
  cur.execute("select post_id from posts where post_id = ?", (post_id, ))
  return bool(cur.fetchone())

def render_weighted_posts(req, weighted_posts):
  entries = []
  already = set()
  for post_id, weight in weighted_posts:
    if post_id in already: continue
    try:
      body = fetch(req.domain(), "api/v1/statuses/%s" % post_id,
                   req.access_token())
    except FetchError as e:
      if e.response.status_code == 404:
        continue
      raise

    entries.append(Entry(body))
    already.add(post_id)

  return [entry.render(req) for entry in entries]

def prepare_feed(req, ignore_post_ids=set()):
  # I can't figure out how to do a list placeholder like "in (?)" with
  # sqlite, so I'm falling back to construcing the query without
  # placeholders.  This is risky, because a mistake gives sql
  # injection, but this particular construction is safe because it is
  # filtered to only numbers.
  safe_ignore_post_ids = ",".join(
    x for x in ignore_post_ids if x.isdigit())

  cur, con = req.db()
  cur.execute("select p.post_id, ifnull(aw.weight, 1) from posts p"
              " left join acct_weights aw"
              "   on aw.acct = p.acct"
              "   and aw.follow = p.post_acct"
              " left join views v"
              "   on v.acct = p.acct"
              "   and v.post_id = p.post_id"
              " where p.acct = ?"
              "   and v.post_id is null" # exclude viewed posts
              "   and p.post_id not in (%s)"
              " order by ifnull(aw.weight, 1) desc, p.created_at desc"
              " limit 10" % safe_ignore_post_ids, (req.acct(), ))
  weighted_posts = []
  response = cur.fetchall()
  if response:
    weighted_posts = [(post_id, int(weight)) for post_id, weight in response]

  post_ids = [x[0] for x in weighted_posts]

  intersection = (set(int(x) for x in post_ids) &
                  set(int(x) for x in ignore_post_ids))
  if intersection:
    raise Exception(intersection)

  return render_weighted_posts(req, weighted_posts), post_ids

def more_feed_json(req):
  ignore_post_ids = json.loads(req.query("next"))
  rendered_entries, post_ids = prepare_feed(req, ignore_post_ids)

  return Response(json.dumps({
    "rendered_entries": rendered_entries,
    "next_token": "END" if not post_ids else "NA",
  }), content_type="application/json")


def feed(req, history=False):
  _, username, domain = req.acct().split("@")
  if not os.path.exists(client_config_fname(domain)):
    raise Exception("Bad user: %s" % acct)

  cur, con = req.db()
  if history:
    rendered_entries, next_token = prepare_history(req)
    rendered_entries = "\n".join(rendered_entries)
    more_content_path = "more_history_json"
  else:
    rendered_entries = ""
    more_content_path = "more_feed_json"
    next_token = "NA";

  hidden = ""
  if history:
    hidden = hide_elements("#alldone")

  subs = {
    'raw_css': template('css') + hidden,
    'raw_header': template(
      'partial_header',
      website=req.website,
      csrf=req.csrf(),
    ),
    'acct': req.acct(),
    'raw_entries': rendered_entries,
    'raw_next_token': json.dumps(next_token),
    'raw_view_tracker_script': template(
      'view_tracker_script',
      raw_vote_script=template('vote_script'),
      csrf=req.csrf(),
      more_content_url=req.make_path(more_content_path),
      populate_feed_url=req.make_path("populate_feed_json"),
      should_track_views="false" if history else "true",
      view_ping_url=req.make_path("view_ping")),
  }

  return Response(template("feed", subs))

def history(req):
  return feed(req, history=True)

def auth(req):
  redirect_url = req.make_path("auth2")

  if not req.form_vals():
    return redirect(website)

  acct = req.form_vals()[b'acct'][0].decode('utf-8')

  if not acct.startswith("@"):
    acct = "@" + acct

  if not user_allowed(acct):
    return Response("not authorized", status="403 Forbidden")

  _, _, domain = acct.split("@")

  if not os.path.exists(client_config_fname(domain)):
    create_client(domain, redirect_url)

  with open(client_config_fname(domain)) as inf:
    client_config = json.load(inf)

  if "error" in client_config:
    raise Exception("Client creation failed: %r" % client_config["error"])

  return Response(
    redirect("https://%s/oauth/authorize?"
             "client_id=%s&scope=read+write&redirect_uri=%s"
             "&response_type=code" % (
               domain, client_config["client_id"], redirect_url)),
    set_cookie("shrubgrazer-acct", acct, strict=False))

def auth2(req):
  untrusted_acct = req.cookies['shrubgrazer-acct'].value
  if not user_allowed(untrusted_acct):
    return Response("not authorized", status="403 Forbidden")

  _, untrusted_username, domain = untrusted_acct.split("@")
  if not os.path.exists(client_config_fname(domain)):
    # should never happen, since we already validated the acct
    return Response("not authorized", status="403 Forbidden")

  with open(client_config_fname(domain)) as inf:
    client_config = json.load(inf)

  resp = subprocess.check_output(
    ["%s/get-user-token.sh" % SCRIPT_DIR,
     client_config['client_id'],
     client_config['client_secret'],
     client_config['redirect_uri'],
     req.query('code'),
     domain])

  access_token = json.loads(resp)['access_token']

  verification = fetch(
    domain, "/api/v1/accounts/verify_credentials", access_token)
  if verification["username"] != untrusted_username:
    return Response("credential verification failed for %s" % (
      untrusted_acct), status="403 Forbidden")
  acct = untrusted_acct
  csrf = secrets.token_urlsafe(32)

  cur, con = req.db()
  cur.execute("insert or replace into accts(acct, csrf) values(?, ?)",
              (acct, csrf))
  con.commit()

  return Response(redirect(req.website),
                  set_cookie('shrubgrazer-access-token',
                             access_token) +
                  set_cookie('shrubgrazer-csrf-token', csrf))

def validate_csrf(req, strict=True):
  if 'shrubgrazer-csrf-token' in req.cookies:
    expected_csrf = req.cookies['shrubgrazer-csrf-token'].value
    actual_csrf = req.query('csrf')
    if expected_csrf and expected_csrf != actual_csrf:
      raise Exception("bad csrf token")
  elif strict:
    raise Exception("missing shrubgrazer-csrf-token cookie")

def unconditional_logout(req):
  return Response(redirect(req.website),
                  delete_cookies('shrubgrazer-access-token',
                                 'shrubgrazer-acct',
                                 'shrubgrazer-csrf-token'))

def logout(req):
  validate_csrf(req, strict=False)
  return unconditional_logout(req)

def clear_history(req):
  validate_csrf(req)

  cur, con = req.db()
  cur.execute("delete from views where acct=?", (req.acct(), ));
  con.commit()

  return Response(redirect(req.website))

def view_ping(req):
  validate_csrf(req)

  csrf = req.query('csrf')
  post_id = req.query('post_id')

  ts = int(time.time())
  post_id = int(post_id)

  cur, con = req.db()
  cur.execute("insert or ignore into views(acct, post_id, ts) "
              "values(?, ?, ?)", (req.acct(), post_id, ts))
  con.commit()

  return Response("noted")

def favorite_json(req):
  validate_csrf(req)

  response = fetch(req.domain(),
                   "api/v1/statuses/%s/%s" % (
    req.query("post_id"),
    {"1": "favourite",
     "-1": "unfavourite"}[req.query("direction")]),
                    req.access_token(),
                   post=True)

  return Response(json.dumps({
    "star": "\u2605" if response['favourited'] else "\u2606"
  }), content_type="application/json")

def reply_json(req):
  validate_csrf(req)

  message = req.query("message").strip()
  if not message:
    return Response(json.dumps({
      "error": "empty post",
    }), content_type="application/json")

  parent_id = req.query("parent_id")
  depth = int(req.query("depth"))

  response = fetch(
    req.domain(),
    "api/v1/statuses",
    req.access_token(),
    post=True,
    headers={
      "Idempotency-Key": str(hash(req.acct() + message + parent_id))
    },
    data={
      "status": message,
      "in_reply_to_id": parent_id,
      "visibility": "unlisted",
    })
  return Response(json.dumps({
    "raw_post": Entry(response).render(req, depth),
  }), content_type="application/json")

def vote_json(req, delta):
  validate_csrf(req)
  cur, con = req.db()
  cur.execute("select weight from acct_weights"
              " where acct = ?"
              "   and follow = ?", (req.acct(), req.query('follow_id')))
  response = cur.fetchone()
  if response:
    old_weight, = response
  else:
    old_weight = 1

  new_weight = int(old_weight + delta)
  cur.execute("insert or replace into acct_weights (acct, follow, weight)"
              " values (?, ?, ?)",
              (req.acct(), req.query('follow_id'), new_weight))
  con.commit()

  return Response(json.dumps({
    "weight": new_weight
  }), content_type="application/json")

def upvote_json(req):
  return vote_json(req, 1)

def downvote_json(req):
  return vote_json(req, -1)


def logged_out_home(req):
  subs = {
    'raw_css': template('css') + hide_elements("#loggedin"),
    'raw_header': template(
      'partial_header',
      website=req.website,
      csrf='')
  }
  return Response(template("welcome", subs))

def settings(req):
  cur, con = req.db()
  cur.execute("select follow, weight from acct_weights"
              " where acct = ?"
              " order by follow desc", (req.acct(), ))
  raw_follow_weights = [
    template("partial_settings_weights", subs={
      "follow": follow,
      "csrf": req.csrf(),
      'up_url': req.make_path(
        "upvote?csrf=%s&follow_id=%s" % (req.csrf(), follow)),
      'down_url': req.make_path(
        "downvote?csrf=%s&follow_id=%s" % (req.csrf(), follow)),
      'weight': int(weight)
    })
    for (follow, weight) in cur.fetchall()]

  subs = {
    'raw_css': template('css'),
    'raw_header': template(
      'partial_header',
      website=req.website,
      csrf=req.csrf()),
    'raw_vote_script': template('vote_script'),
    'raw_follow_weights': ''.join(raw_follow_weights),
  }

  return Response(template("settings", subs))

ROUTES = {
  "": feed,
  "auth": auth,
  "auth2": auth2,
  "view_ping": view_ping,
  "clear_history": clear_history,
  "history": history,
  "more_history_json": more_history_json,
  "more_feed_json": more_feed_json,
  "populate_feed_json": populate_feed_json,
  "upvote": upvote_json,
  "downvote": downvote_json,
  "favorite": favorite_json,
  "reply": reply_json,
  "settings": settings,
}

def start(environ, start_response):
  req = Request(environ)

  if re.match(".*/post/[0-9]*$", req.path):
    basepath, _, post_id, = req.path.rsplit("/", 2)
    req.website = "https://%s%s/" % (req.host, basepath)
    return post(post_id, req)

  if req.csrf():
    cur, con = req.db()
    cur.execute("select acct from accts where csrf = ?", (req.csrf(), ))
    if not cur.fetchone():
      return unconditional_logout(req)

  if req.page == "logout":
    return logout(req)

  if not req.page and not req.logged_in():
    return logged_out_home(req)

  if req.page not in ROUTES:
    return Response("Unknown URL", status="400 Bad Request")

  return ROUTES[req.page](req)

def die500(start_response, e):
  trb = "%s: %s\n\n%s" % (e.__class__.__name__, e, traceback.format_exc())
  start_response('500 Internal Server Error', [('content-type', 'text/plain')])
  return trb

def application(environ, start_response):
  try:
    response = start(environ, start_response)
    output = response.output
    headers = response.headers
    headers.append(('content-type', response.content_type))
    start_response(response.status, headers)
  except Exception as e:
    output = die500(start_response, e)
  output = output.encode('utf8')
  return output,
