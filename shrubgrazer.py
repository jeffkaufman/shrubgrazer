#!/usr/bin/env python3

import os
import re
import json
import html
import string
import urllib
import requests
import traceback
import subprocess
import http.cookies

script_dir = os.path.dirname(__file__)

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

class Entry:
  def __init__(self, entry_json):
    self.boosters = []
    while hasall(entry_json, 'reblog') and not hasall(entry_json, 'content'):
      self.boosters.append(get_display_names(entry_json))
      entry_json = entry_json['reblog']

    self.display_name, self.acct = get_display_names(entry_json)

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

  subs = {
    'raw_css': template('css'),
    'raw_header': template('partial_header', website=website),
    'raw_ancestors': rendered_ancestors,
    'raw_post': root.render(),
    'raw_toggle_script': template('toggle_script'),
  }

  return Response(template("post", subs))

def feed(access_token, acct, website):
  _, username, domain = acct.split("@")
  if not os.path.exists(client_config_fname(domain)):
    raise Exception("Bad user: %s" % acct)

  max_id_arg = ""

  entries = []
  for i in range(1):
    entries.extend(fetch(domain, "api/v1/timelines/home?limit=40%s" % max_id_arg,
                         access_token))
    max_id_arg = "&max_id=%s" % entries[-1]["id"]

  rendered_entries = [
    Entry(entry).render(url_prefix="post/")
    for entry in entries
  ]

  subs = {
    'raw_css': template('css'),
    'raw_header': template('partial_header', website=website),
    'raw_entries': rendered_entries,
  }

  return Response(template("feed", subs))

def home(cookies, website):
  if 'shrubgrazer-access-token' not in cookies:
    subs = {
      'raw_css': template('css'),
      'raw_header': template('partial_header', website=website),
    }
    return Response(template("welcome", subs))
  return feed(cookies['shrubgrazer-access-token'].value,
              cookies['shrubgrazer-acct'].value,
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
  redirect_url = "https://%sauth2" % website

  request_body_size = int(environ.get('CONTENT_LENGTH', 0) or 0)
  form_vals = urllib.parse.parse_qs(
    environ['wsgi.input'].read(request_body_size))

  if not form_vals:
    return redirect(re.sub("/auth$", "/", path))

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


  return Response(redirect(website),
                  set_cookie('shrubgrazer-access-token', access_token))

def removeprefix(s, prefix):
  if s.startswith(prefix):
    return s[len(prefix):]
  return s

def removesuffix(s, suffix):
  if s.endswith(suffix):
    return s[:-len(suffix)]
  return s

def logout(website):
  return Response(redirect(website),
                  delete_cookies('shrubgrazer-access-token',
                                 'shrubgrazer-acct'))

def start(environ, start_response):
  cookies = http.cookies.BaseCookie(environ.get('HTTP_COOKIE', ''))
  path = environ["PATH_INFO"]

  if re.match(".*/post/[0-9]*$", path):
    website, _, post_id, = path.rsplit("/", 2)
    return post(post_id, cookies, website=website + "/")

  website, page = path.rsplit("/", 1)
  website = website + "/"

  if not page:
    return home(cookies, website)

  if page == "logout":
    return logout(website)

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
