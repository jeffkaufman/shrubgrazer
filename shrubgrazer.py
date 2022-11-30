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

script_dir = os.path.dirname(__file__)
db_filename = "%s/sg.db" % script_dir

def initialize_db(cur):
  cur.execute("create table accts("
              " acct text primary key,"
              " csrf text unique)")
  cur.execute("create table acct_weights("
              " acct text,"
              " follow text,"
              " weight real, "
              " primary key (acct, follow))")
  cur.execute("create table views("
              " acct text,"
              " post_id integer,"
              " ts integer,"
              " primary key (acct, post_id))")

def get_cursor():
  initialize = False
  if not os.path.exists(db_filename):
    initialize = True

  con = sqlite3.connect(db_filename)
  cur = con.cursor()

  if initialize:
    initialize_db(cur)

  return cur, con

def hasall(d, *vals):
  for val in vals:
    if not d.get(val, None):
      return False
  return True

class Response:
  def __init__(self, output="", headers=[]):
    self.output = output
    self.headers = headers

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

def get_display_names(entry_json):
  display_name = entry_json['account']['display_name']
  acct = entry_json['account']['acct']
  if not display_name:
    display_name = acct
    acct = ""

  # remove unrecognized emoji colon codes
  display_name = re.sub(":.*:", "", display_name)

  return display_name, acct

def epoch(timestring):
  return int(time.mktime(
    dateutil.parser.parse(timestring)
    .astimezone(dateutil.tz.tzlocal())
    .timetuple()))

class Entry:
  def __init__(self, entry_json):
    self.created_at = epoch(entry_json['created_at'])

    self.boosters = []
    while hasall(entry_json, 'reblog') and not hasall(entry_json, 'content'):
      self.boosters.append(get_display_names(entry_json))
      entry_json = entry_json['reblog']

    self.display_name, self.acct = get_display_names(entry_json)

    self.post_id = entry_json["id"]
    self.view_url = entry_json["id"]
    self.external_url = entry_json["url"]
    self.flavor = 'standard'
    self.raw_ts = entry_json['created_at'].split("T")[0]
    self.raw_body = entry_json['content']
    self.children = []
    self.attachments = []

    if hasall(entry_json, 'card'):
      self.attachments.append(Card(entry_json['card']))

    for media_attachment in entry_json.get('media_attachments', []):
      self.attachments.append(Attachment(media_attachment))

    if hasall(entry_json, 'reblog'):
      child = Entry(entry_json['reblog'])
      child.flavor = 'reblog'
      self.flavor = 'boost'
      self.children.append(child)

  def render(self, depth=0, url_prefix=""):
    subs = dict(
      (k, getattr(self, k))
      for k in dir(self)
      if not k.startswith('__'))

    subs['parity'] = str(depth % 2)
    subs['raw_children'] = [
      child.render(depth=depth+1, url_prefix=url_prefix)
      for child in self.children]

    subs['raw_boosted_by'] = [
      "<tr><td colspan=2>"
      "<span class='display_name booster_name'>&uarr; %s</span> "
      "<span class=acct>%s</span></td>" % (
        html.escape(display_name), html.escape(acct))
      for display_name, acct in self.boosters]

    subs['raw_attachments'] = [
      attachment.render() for attachment in self.attachments]
    subs['view_url'] = url_prefix + subs['view_url']

    return template("partial_post", subs)

def fetch(domain, path, access_token=None):
  headers = {}
  if access_token:
    headers["Authorization"] = "Bearer %s" % access_token

  return requests.get("https://%s/%s" % (domain, path), headers=headers).json()

TEMPLATES = {}

def template(template_name, subs={}, **kwargs):
  if template_name not in TEMPLATES:
    with open("%s/templates/%s.html" % (script_dir, template_name)) as inf:
      t = inf.read()
    TEMPLATES[template_name] = string.Template(t)

  safe_subs = {}
  for k, v in {**subs, **kwargs}.items():
    if type(v) == type([]):
      v = "\n".join([x for x in v if type(x) == type("")])

    if v is None:
      v = ''

    if type(v) == type(1):
      v = str(v)

    if type(v) != type(""):
      continue

    if not k.startswith("raw_"):
      v = html.escape(v)
    safe_subs[k] = v

  try:
    return TEMPLATES[template_name].substitute(safe_subs)
  except Exception:
    with open("%s/details.txt" % script_dir, "w") as outf:
      outf.write(json.dumps(safe_subs))
    raise


def post(post_id, cookies, website):
  if not re.match('^[0-9]+$', post_id):
    return "invalid post id\n"

  domain = "mastodon.mit.edu"
  access_token = None
  if 'shrubgrazer-access-token' in cookies:
    _, _, domain = cookies['shrubgrazer-acct'].value.split("@")
    access_token = cookies['shrubgrazer-access-token'].value

  body = fetch(domain, "api/v1/statuses/%s" % post_id, access_token)
  context = fetch(domain, "api/v1/statuses/%s/context" % post_id, access_token)

  rendered_ancestors = [
    Entry(ancestor).render()
    for ancestor in context["ancestors"]]

  root = Entry(body)
  root.flavor = 'root'
  children_by_id = {post_id: root}

  for child_json in context["descendants"]:
    child = Entry(child_json)

    children_by_id[child_json["id"]] = child
    children_by_id[child_json["in_reply_to_id"]].children.append(child)

  hidden = hide_elements("#earlier", "#later")
  if 'shrubgrazer-csrf-token' in cookies:
    csrf_token = cookies['shrubgrazer-csrf-token'].value
  else:
    csrf_token = ""
    hidden += hide_elements("#logout")

  subs = {
    'raw_css': template('css') + hidden,
    'raw_header': template(
      'partial_header',
      website=website,
      csrf=csrf_token,
      earlier="",
      later=""),
    'raw_ancestors': rendered_ancestors,
    'raw_post': root.render(),
    'raw_toggle_script': template('toggle_script'),
    'raw_view_tracker_script': template(
      'view_tracker_script',
      csrf=csrf_token,
      view_ping_url="%sview_ping" % website),
  }

  return Response(template("post", subs))

ONE_HOUR_S=60*60

def feed(access_token, acct, csrf_token, raw_ts, website):
  _, username, domain = acct.split("@")
  if not os.path.exists(client_config_fname(domain)):
    raise Exception("Bad user: %s" % acct)

  max_ts = int(time.time())
  if raw_ts:
    max_ts = int(raw_ts)

  cur, con = get_cursor()
  cur.execute("select post_id from views "
              "where acct=? and ts < ?", (acct, max_ts))
  viewed_post_ids = set(x[0] for x in cur.fetchall())

  # TODO: Time jumps aren't right.  I think these could be very
  # natural, but right now they're not.  Properties I want:
  #  1. At each timestamp you see the world as you would have at that time
  #     - no posts considered from after the timestamp
  #     - no views counted from after the timestamp
  #     - I think this is implemented correctly
  #  2. By clicking back and forward every post is accessible
  #
  # Thoughts:
  #  - I think this is a question of choosing the right jump points.
  #  - Right now jump points are kind of arbitrary.
  #  - A bad case happens when you have:
  #      jp1 < t_post < t_view < jp2
  #  - This means that for every post + view pair we need to have a
  #    jump point between them
  #  - But we can collapse:
  #     - jp1 < t_postA < t_postB < jp2 < t_viewA < t_viewB < now
  #  - Can't always collapse, if t_viewA < t_postB
  #     - jp1 < t_postA < jp2 < t_viewA < t_postB < jp3 < t_viewB < now

  # jumping backwards
  #  - find the most recent view more than an hour ago
  #  - go back an hour before that to skip views in close succession
  cur.execute("select ts from views "
              "where acct=? and ts < ?"
              "order by ts desc "
              "limit 1", (acct, max_ts - ONE_HOUR_S))
  result = cur.fetchone()
  if result:
    earlier_ts, = result
    earlier_ts -= ONE_HOUR_S
  else:
    cur.execute("select ts from views "
                "where acct=?"
                "order by ts asc "
                "limit 1", (acct, ))
    result = cur.fetchone()
    if result:
      earlier_ts, = result
    else:
      earlier_ts = 1000000000

  # jumping forwards
  # - find the most recent view at least an hour from then
  # - if it's in the future take people to the main feed
  cur.execute("select ts from views "
              "where acct=? and ts > ?"
              "order by ts asc "
              "limit 1", (acct, max_ts + ONE_HOUR_S))
  result = cur.fetchone()
  if result:
    later_ts, = result
    if later_ts > time.time():
      later_ts = ""
  else:
    later_ts = ""

  max_id_arg = ""
  entries = []
  for i in range(1):
    entries.extend(fetch(domain, "api/v1/timelines/home?limit=40%s" % max_id_arg,
                         access_token))
    max_id_arg = "&max_id=%s" % entries[-1]["id"]

  entries = [Entry(entry) for entry in entries]
  rendered_entries = [
    entry.render(url_prefix="post/")
    for entry in entries
    if int(entry.post_id) not in viewed_post_ids and entry.created_at < max_ts
  ]

  hidden = ""
  if raw_ts and raw_ts == str(earlier_ts):
    hidden = hide_elements("#earlier")
  elif not raw_ts:
    hidden = hide_elements("#later")

  subs = {
    'raw_css': template('css') + hidden,
    'raw_header': template(
      'partial_header',
      website=website,
      csrf=csrf_token,
      earlier="%s%s" % (website, earlier_ts),
      later="%s%s" % (website, later_ts)
    ),
    'raw_entries': rendered_entries,
    'raw_view_tracker_script': template(
      'view_tracker_script',
      csrf=csrf_token,
      view_ping_url="%sview_ping" % website),
  }

  return Response(template("feed", subs))

def hide_elements(*selectors):
  return "<style>%s{display:none}</style>" % ", ".join(selectors)

def home(cookies, website, ts=None):
  if 'shrubgrazer-access-token' not in cookies:
    subs = {
      'raw_css': template('css') + hide_elements("#logout", "#earlier", "#later"),
      'raw_header': template(
        'partial_header',
        website=website,
        csrf='',
        earlier="",
        later=""),
    }
    return Response(template("welcome", subs))
  return feed(cookies['shrubgrazer-access-token'].value,
              cookies['shrubgrazer-acct'].value,
              cookies['shrubgrazer-csrf-token'].value,
              ts,
              website=website)

def create_client(domain, redirect_url):
  website = re.sub("/auth2$", "/", redirect_url)
  subprocess.check_call(["%s/create-client.sh" % script_dir,
                         domain,
                         redirect_url,
                         website,
                         client_config_fname(domain)])

def redirect(url):
  return template("redirect", url=url)

def client_config_fname(domain):
  return "%s/%s.client-config.json" % (script_dir, domain)

def set_cookie(k, v):
  return [
    ("set-cookie",
     "%s=%s; Secure; HttpOnly; SameSite=Strict; Max-Age=%s" % (
       k, v, 365*24*60*60))]

def delete_cookies(*cookies):
  return [delete_cookie(cookie) for cookie in cookies]

def delete_cookie(cookie):
  return (
    "set-cookie",
    "%s=deleted; Secure; HttpOnly; SameSite=Strict; Max-Age=0" % cookie)

def auth(cookies, environ, website):
  redirect_url = "%sauth2" % website

  request_body_size = int(environ.get('CONTENT_LENGTH', 0) or 0)
  form_vals = urllib.parse.parse_qs(
    environ['wsgi.input'].read(request_body_size))

  if not form_vals:
    return redirect(website)

  acct = form_vals[b'acct'][0].decode('utf-8')

  if not acct.startswith("@"):
    acct = "@" + acct

  with open("%s/users.json" % script_dir) as inf:
    allowed_users = json.load(inf)

  if acct not in allowed_users:
    return "not authorized"

  _, username, domain = acct.split("@")

  if not os.path.exists(client_config_fname(domain)):
    create_client(domain, redirect_url)

  with open(client_config_fname(domain)) as inf:
    client_config = json.load(inf)

  return Response(
    redirect("https://%s/oauth/authorize?"
             "client_id=%s&scope=read&redirect_uri=%s&response_type=code" % (
               domain, client_config["client_id"], redirect_url)),
    set_cookie("shrubgrazer-acct", acct))

def auth2(cookies, environ, website):
  acct = cookies['shrubgrazer-acct'].value
  _, username, domain = acct.split("@")
  if not os.path.exists(client_config_fname(domain)):
    raise Exception("Bad user: %s" % acct)

  query = urllib.parse.parse_qs(environ['QUERY_STRING'])

  with open(client_config_fname(domain)) as inf:
    client_config = json.load(inf)

  resp = subprocess.check_output(
    ["%s/get-user-token.sh" % script_dir,
     client_config['client_id'],
     client_config['client_secret'],
     client_config['redirect_uri'],
     query['code'][0],
     domain])

  access_token = json.loads(resp)['access_token']

  verification = fetch(
    domain, "/api/v1/accounts/verify_credentials", access_token)
  if verification["username"] != username:
    raise Exception("Credential verification failed for %s" % (acct))

  csrf = secrets.token_urlsafe(32)

  cur, con = get_cursor()
  cur.execute("insert or replace into accts(acct, csrf) values(?, ?)",
              (acct, csrf))
  con.commit()

  return Response(redirect(website),
                  set_cookie('shrubgrazer-access-token',
                             access_token) +
                  set_cookie('shrubgrazer-csrf-token', csrf))

def removeprefix(s, prefix):
  if s.startswith(prefix):
    return s[len(prefix):]
  return s

def removesuffix(s, suffix):
  if s.endswith(suffix):
    return s[:-len(suffix)]
  return s

def validate_csrf(cookies, query):
  if 'shrubgrazer-csrf-token' in cookies:
    expected_csrf = cookies['shrubgrazer-csrf-token'].value
    actual_csrf, = query['csrf']
    if expected_csrf and expected_csrf != actual_csrf:
      raise Exception("bad csrf token")

def logout(cookies, query, website):
  validate_csrf(cookies, query)
  return Response(redirect(website),
                  delete_cookies('shrubgrazer-access-token',
                                 'shrubgrazer-acct',
                                 'shrubgrazer-csrf-token'))

def view_ping(cookies, query):
  validate_csrf(cookies, query)

  csrf, = query['csrf']
  post_id, = query['post_id']

  ts = int(time.time())

  cur, con = get_cursor()
  cur.execute("select acct from accts where csrf=?", (csrf, ))
  acct, = cur.fetchone()
  cur.execute("insert or ignore into views(acct, post_id, ts) "
              "values(?, ?, ?)", (acct, post_id, ts))
  con.commit()

  return Response("noted")

def full_website(host, path):
  return "https://%s%s/" % (host, path)

def start(environ, start_response):
  cookies = http.cookies.BaseCookie(environ.get('HTTP_COOKIE', ''))
  path = environ["PATH_INFO"]
  host = environ["HTTP_HOST"]

  if re.match(".*/post/[0-9]*$", path):
    basepath, _, post_id, = path.rsplit("/", 2)
    return post(post_id, cookies, website=full_website(host, basepath))

  basepath, page = path.rsplit("/", 1)
  website = full_website(host, basepath)

  query = urllib.parse.parse_qs(environ['QUERY_STRING'])

  # TODO(jefftk): fix before 2286-11-20
  if not page or page.isdigit() and len(page) == 10:
    return home(cookies, website, ts=page)

  if page == "view_ping":
    return view_ping(cookies, query)

  if page == "logout":
    return logout(cookies, query, website)

  if page == "auth":
    return auth(cookies, environ, website)

  if page == "auth2":
    return auth2(cookies, environ, website)

  return Response("unknown url\n")

def die500(start_response, e):
  trb = "%s: %s\n\n%s" % (e.__class__.__name__, e, traceback.format_exc())
  start_response('500 Internal Server Error', [('content-type', 'text/plain')])
  return trb

def application(environ, start_response):
  try:
    response = start(environ, start_response)
    output = response.output
    headers = response.headers
    headers.append(('content-type', 'text/html'))
    start_response('200 OK', headers)
  except Exception as e:
    output = die500(start_response, e)
  output = output.encode('utf8')
  return output,

def server():
  from wsgiref.simple_server import make_server

  # run on port 8010
  make_server('',8010,application).serve_forever()

if __name__ == "__main__":
  server()
