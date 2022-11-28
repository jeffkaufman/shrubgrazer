#!/usr/bin/env python3

import os
import re
import json
import html
import string
import requests
import traceback

# TODO: make configurable
SERVER="https://mastodon.mit.edu"
script_dir = os.path.dirname(__file__)

def fetch(path):
  # TODO: add header "Authorization: Bearer [token]"
  return requests.get("%s/%s" % (SERVER, path)).json()

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
    
  return dict(
    view_url=s["id"],
    external_url=s["url"],
    display_name=display_name,
    acct=acct,
    flavor='standard',
    ts=s['created_at'].split("T")[0],
    raw_body=s['content'],
    children=[])

def post(post_id):
  if not re.match('^[0-9]+$', post_id):
    return "invalid post id\n"

  body = fetch("api/v1/statuses/%s" % post_id)
  context = fetch("api/v1/statuses/%s/context" % post_id)

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
    'raw_ancestors': rendered_ancestors,
    'raw_post': rendered_post_and_children,
  }
  
  return template("post", subs)

def removeprefix(s, prefix):
  if s.startswith(prefix):
    return s[len(prefix):]
  return s

def start(environ, start_response):
  path = environ["PATH_INFO"]
  path = removeprefix(path, "/")
  path = removeprefix(path, "shrubgrazer/")

  pieces = path.split("/")

  if len(pieces) == 1 and not pieces[0]:
    return home()

  if len(pieces) == 2 and pieces[0] == "post":
    _, post_id = pieces
    return post(post_id)

  return "unknown url\n"

def die500(start_response, e):
  trb = "%s: %s\n\n%s" % (e.__class__.__name__, e, traceback.format_exc())
  start_response('500 Internal Server Error', [('content-type', 'text/plain')])
  return trb

def application(environ, start_response):
  try:
    output = start(environ, start_response)
    if output is None:
      output = ''
    start_response('200 OK', [('content-type', 'text/html')])
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
