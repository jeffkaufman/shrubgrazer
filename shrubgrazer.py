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

def fetch(domain, path, access_token=None):
  headers = {}
  if access_token:
    headers["Authorization"] = "Bearer %s" % access_token
  return requests.get("https://%s/%s" % (domain, path),
                      headers=headers).json()

TEMPLATES = {}

def template(template_name, subs={}, **kwargs):
  if template_name not in TEMPLATES:
    with open("%s/templates/%s.html" % (script_dir, template_name)) as inf:
      t = inf.read()
    TEMPLATES[template_name] = string.Template(t)

  safe_subs = {}
  for k, v in {**subs, **kwargs}.items():
    if type(v) == type([]):
      v = "\n".join(v)

    if v is None:
      v = ''

    if not k.startswith("raw_"):
      v = html.escape(v)
    safe_subs[k] = v

  return TEMPLATES[template_name].substitute(safe_subs)

def render_child_tree(node, depth=0):
  node['parity'] = str(depth % 2)
  node['raw_children'] = [render_child_tree(child, depth+1)
                          for child in node['children']]
  del node['children']
  return template("partial_post", subs=node)

def make_post_dict(s):
  display_name=s['account']['display_name']
  acct=s['account']['acct']

  if not display_name:
    display_name = acct
    acct = ""

  d = dict(
    view_url=s["id"],
    external_url=s["url"],
    display_name=display_name,
    acct=acct,
    flavor='standard',
    ts=s['created_at'].split("T")[0],
    raw_body=s['content'],
    children=[])

  if 'reblog' in s and s['reblog']:
    d['children'] = [make_post_dict(s['reblog'])]

  return d

def post(post_id, cookies):
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
    render_child_tree(make_post_dict(ancestor))
    for ancestor in context["ancestors"]]

  root = make_post_dict(body)
  root['flavor'] = 'root'
  children_by_id = {post_id: root}

  for child in context["descendants"]:
    child_dict = make_post_dict(child)

    children_by_id[child["id"]] = child_dict
    children_by_id[child["in_reply_to_id"]]['children'].append(child_dict)

  rendered_post_and_children = render_child_tree(root)

  subs = {
    'raw_css': template('css'),
    'raw_ancestors': rendered_ancestors,
    'raw_post': rendered_post_and_children,
  }

  return template("post", subs)

def feed(access_token, acct):
  _, username, domain = acct.split("@")
  if not os.path.exists(client_config_fname(domain)):
    raise Exception("Bad user: %s" % acct)

  entries = fetch(domain, "api/v1/timelines/home", access_token)

  rendered_entries = []
  for entry in entries:
    rendered_entries.append(render_child_tree(make_post_dict(entry)))

  subs = {
    'raw_css': template('css'),
    'raw_entries': rendered_entries
  }

  return template("feed", subs)

def home(cookies):
  if 'shrubgrazer-access-token' not in cookies:
    return template("welcome")
  return feed(cookies['shrubgrazer-access-token'].value,
              cookies['shrubgrazer-acct'].value)

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
  return {"set-cookie":
          "%s=%s; Secure; HttpOnly; SameSite=Strict; Max-Age=%s" % (
            k, v, 365*24*60*60)}

def auth(cookies, environ):
  host = environ['HTTP_HOST']
  path = environ["PATH_INFO"]

  redirect_path = re.sub("/auth$", "/auth2", path)
  redirect_url = "https://%s%s" % (host, redirect_path)

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

  return [
    redirect("https://%s/oauth/authorize?"
             "client_id=%s&scope=read&redirect_uri=%s&response_type=code" % (
               domain, client_config["client_id"], redirect_url)),
    set_cookie("shrubgrazer-acct", acct)]

def auth2(cookies, environ):
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

  host = environ['HTTP_HOST']
  path = environ["PATH_INFO"]
  redirect_url = "https://%s%s" % (host, re.sub("/auth2$", "/", path))

  return [redirect(redirect_url),
          set_cookie('shrubgrazer-access-token', access_token)]

def removeprefix(s, prefix):
  if s.startswith(prefix):
    return s[len(prefix):]
  return s

def removesuffix(s, suffix):
  if s.endswith(suffix):
    return s[:-len(suffix)]
  return s

def start(environ, start_response):
  path = environ["PATH_INFO"]
  path = removeprefix(path, "/")
  path = removeprefix(path, "shrubgrazer/")

  pieces = path.split("/")
  cookies = http.cookies.BaseCookie(environ.get('HTTP_COOKIE', ''))

  if len(pieces) == 1 and not pieces[0]:
    return home(cookies)

  if len(pieces) == 1 and pieces[0] == "auth":
    return auth(cookies, environ)

  if len(pieces) == 1 and pieces[0] == "auth2":
    return auth2(cookies, environ)

  if len(pieces) == 2 and pieces[0] == "post":
    _, post_id = pieces
    return post(post_id, cookies)

  return "unknown url\n"

def die500(start_response, e):
  trb = "%s: %s\n\n%s" % (e.__class__.__name__, e, traceback.format_exc())
  start_response('500 Internal Server Error', [('content-type', 'text/plain')])
  return trb

def application(environ, start_response):
  try:
    output = start(environ, start_response)
    new_headers = {}

    if type(output) == type([]):
      output, new_headers = output

    if output is None:
      output = ''

    headers = [('content-type', 'text/html')]
    for k, v in new_headers.items():
      headers.append((k, v))

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
