#!/usr/bin/env python
import collections
import json
import os.path
import random
import re
import sys
import traceback
import urllib
import wsgiref.handlers
import wsgiref.simple_server
import webapp2
import tornado.template
from google.appengine.api import memcache
from google.appengine.api import users
from google.appengine.ext import blobstore
from google.appengine.ext import ndb
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext.webapp import util
import wifipacket


BROADCAST = 'ff:ff:ff:ff:ff:ff'

loader = tornado.template.Loader('.')


def GoogleLoginRequired(func):
  def Handler(self, *args, **kwargs):
    user = users.get_current_user()
    if not user:
      self.redirect(users.create_login_url('/'))
    elif not user.email().endswith('@google.com'):
      self.response.set_status(401, 'Unauthorized')
      self.response.write("Sorry.  You're not an authorized user.")
    else:
      return func(self, *args, **kwargs)
  return Handler


class PcapData(ndb.Model):
  create_time = ndb.DateTimeProperty(auto_now_add=True)
  filename = ndb.StringProperty()
  show_hosts = ndb.StringProperty(repeated=True)
  aliases = ndb.PickleProperty()


class _BaseHandler(webapp2.RequestHandler):
  def render(self, template, **kwargs):
    d = dict()
    d.update(kwargs)
    self.response.write(loader.load(template).generate(**d))


class MainHandler(_BaseHandler):
  @GoogleLoginRequired
  def get(self):
    upload_url = blobstore.create_upload_url('/upload')
    q = PcapData.query().order(-PcapData.create_time).fetch(10)
    self.render('index.html',
                upload_url=upload_url,
                recents=q)


class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
  def post(self):
    upload_files = self.get_uploads()
    sys.stderr.write('upload: %r\n' % upload_files)
    blob_info = upload_files[0]
    self.redirect('/view/%s' % blob_info.key())


def _Boxes(blob_info):
  boxes = memcache.get(str(blob_info.key()), namespace='boxes')
  if not boxes:
    reader = blob_info.open()
    boxes = collections.defaultdict(lambda: 0)
    for p, frame in wifipacket.Packetize(reader):
      if 'flags' in p and p.flags & wifipacket.Flags.BAD_FCS: continue
      if 'ta' in p and 'ra' in p:
        boxes[p.ta] += 1
        boxes[p.ra] += 1
    memcache.add(key=str(blob_info.key()), value=dict(boxes),
                 namespace='boxes')
  return boxes


class ViewHandler(_BaseHandler):
  @GoogleLoginRequired
  def get(self, blobres):
    blob_info = blobstore.BlobInfo.get(str(urllib.unquote(blobres)))
    capdefault = PcapData.get_or_insert(str('*'), show_hosts=[], aliases={})
    pcapdata = PcapData.get_or_insert(str(blob_info.key()),
                                      filename=blob_info.filename,
                                      show_hosts=[], aliases={})
    try:
      boxes = _Boxes(blob_info)
    except ValueError as e:
      self.response.set_status(500, 'Server error')
      self.response.write('<pre>%s</pre>' % traceback.format_exc())
      return

    cutoff = max(boxes.itervalues()) * 0.01
    cutboxes = [(b, n)
                for b, n
                in sorted(boxes.iteritems(), key=lambda x: -x[1])
                if n >= cutoff and b != BROADCAST]
    other = sum((n for n in boxes.itervalues() if n < cutoff))
    aliases = pcapdata.aliases
    if pcapdata.show_hosts:
      checked = dict((h, 1) for h in pcapdata.show_hosts)
    else:
      checked = {}
      for b, n in cutboxes:
        checked[b] = (n > cutoff * 10)
    for b in boxes.keys():
      if b not in aliases:
        aliases[b] = capdefault.aliases.get(b, b)
    self.render('view.html',
                blob=blob_info,
                boxes=cutboxes,
                other=other,
                aliases=aliases,
                checked=checked)


class SaveHandler(_BaseHandler):
  @GoogleLoginRequired
  def post(self, blobres):
    blob_info = blobstore.BlobInfo.get(str(urllib.unquote(blobres)))
    capdefault = PcapData.get_or_insert(str('*'), show_hosts=[], aliases={})
    pcapdata = PcapData.get_or_insert(str(blob_info.key()),
                                      show_hosts=[], aliases={})
    boxes = _Boxes(blob_info)
    pcapdata.show_hosts = []
    for b in boxes.keys():
      alias = self.request.get('name-%s' % b)
      if alias:
        pcapdata.aliases[b] = alias
        capdefault.aliases[b] = alias
      else:
        pcapdata.aliases[b] = b
      if self.request.get('show-%s' % b):
        pcapdata.show_hosts.append(b)
    capdefault.put()
    pcapdata.put()
    self.response.write('done')


settings = dict(
    debug = 1,
)

wsgi_app = webapp2.WSGIApplication([
    (r'/', MainHandler),
    (r'/upload', UploadHandler),
    (r'/view/([^/]+)$', ViewHandler),
    (r'/save/([^/]+)$', SaveHandler),
], **settings)
