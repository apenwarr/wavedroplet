#!/usr/bin/env python
import collections
import errno
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
DEFAULT_FIELDS = ['seq', 'rate']
AVAIL_FIELDS = ['seq', 'mcs', 'rate', 'retry',
                'type', 'typestr', 'dbm_antsignal', 'dbm_antnoise']

loader = tornado.template.Loader('.')


def _Esc(s):
  """Like tornado.escape.url_escape, but only escapes &, #, and %."""
  out = []
  for c in s:
    if c in ['&', '#', '%']:
      out.append('%%%02X' % ord(c))
    else:
      out.append(c)
  return ''.join(out)


def AllowedEmails():
  try:
    return open('email-allow.txt').read().split()
  except IOError as e:
    if e.errno == errno.ENOENT:
      pass
    else:
      raise
  return []


def GoogleLoginRequired(func):
  def Handler(self, *args, **kwargs):
    user = users.get_current_user()
    if not user:
      self.redirect(users.create_login_url('/'))
    elif (not user.email().endswith('@google.com') and
          user.email() not in AllowedEmails()):
      self.response.set_status(401, 'Unauthorized')
      self.response.write("Sorry.  You're not an authorized user.")
    else:
      return func(self, *args, **kwargs)
  return Handler


class PcapData(ndb.Model):
  create_time = ndb.DateTimeProperty(auto_now_add=True)
  create_user_email = ndb.StringProperty()
  filename = ndb.StringProperty()
  show_hosts = ndb.StringProperty(repeated=True)
  show_fields = ndb.StringProperty(repeated=True)
  aliases = ndb.PickleProperty()

  @staticmethod
  def _GetDefault():
    return PcapData.get_or_insert(str('*'), show_hosts=[], aliases={})

  @staticmethod
  def _GetOrInsertFromBlob(blob_info):
    u = users.get_current_user()
    if u:
      email = u.email()
    else:
      email = '<anonymous>'
    return PcapData.get_or_insert(str(blob_info.key()),
                                  show_hosts=[], aliases={},
                                  filename=blob_info.filename,
                                  create_user_email=email)


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
    reader = blob_info.open()
    try:
      wifipacket.Packetize(reader).next()  # just check basic file header
    except wifipacket.Error:
      blob_info.delete()
      raise
    self.redirect('/view/%s' % blob_info.key())


class DownloadHandler(blobstore_handlers.BlobstoreDownloadHandler):
  def get(self, blobres):
    blob_info = blobstore.BlobInfo.get(str(urllib.unquote(blobres)))
    self.send_blob(blob_info)


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
    capdefault = PcapData._GetDefault()
    pcapdata = PcapData._GetOrInsertFromBlob(blob_info)

    boxes = _Boxes(blob_info)
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
    if not pcapdata.show_fields:
      pcapdata.show_fields = DEFAULT_FIELDS
    for b in boxes.keys():
      if b not in aliases:
        aliases[b] = capdefault.aliases.get(b, b)
    self.render('view.html',
                blob=blob_info,
                boxes=cutboxes,
                other=other,
                aliases=aliases,
                checked=checked,
                obj=pcapdata,
                show_fields=dict((i, 1) for i in pcapdata.show_fields),
                avail_fields=AVAIL_FIELDS)


class SaveHandler(_BaseHandler):
  @GoogleLoginRequired
  def post(self, blobres):
    blob_info = blobstore.BlobInfo.get(str(urllib.unquote(blobres)))
    capdefault = PcapData._GetDefault()
    u = users.get_current_user()
    if u:
      email = u.email()
    else:
      email = 'anonymous'
    sys.stderr.write('stupid user:%r email:%r\n' % (u, u.email()))
    pcapdata = PcapData._GetOrInsertFromBlob(blob_info)
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

    pcapdata.show_fields = []
    for k in AVAIL_FIELDS:
      if self.request.get('key-%s' % k):
        pcapdata.show_fields.append(k)

    capdefault.put()
    pcapdata.put()
    url = ('%s?hosts=%s&keys=%s'
           % (self.request.url.replace('/save/', '/json/'),
              _Esc(','.join(pcapdata.show_hosts)),
              _Esc(','.join(pcapdata.show_fields))))
    self.redirect('//afterquery.appspot.com/?url=%s&chart=traces' % _Esc(url))


class JsonHandler(_BaseHandler):
  @GoogleLoginRequired
  def get(self, blobres):
    # TODO(apenwarr): allow http-level caching
    blob_info = blobstore.BlobInfo.get(str(urllib.unquote(blobres)))
    pcapdata = PcapData._GetOrInsertFromBlob(blob_info)
    aliases = pcapdata.aliases
    show_hosts = self.request.get('hosts').split(',')
    reader = blob_info.open()
    out = collections.defaultdict(list)
    keys = self.request.get('keys', 'seq,rate').split(',')
    timebase = 0
    for i, (p, frame) in enumerate(wifipacket.Packetize(reader)):
      if not timebase: timebase = p.pcap_secs
      ta = p.get('ta')
      ra = p.get('ra')
      if ta not in show_hosts and aliases.get(ta) not in show_hosts:
        ta = ra = '~other'  # '~' causes it to sort last in the list
      elif ta in aliases:
        ta = aliases[ta]
      if ra not in show_hosts and aliases.get(ra) not in show_hosts:
        ta = ra = '~other'  # '~' causes it to sort last in the list
      elif ra in aliases:
        ra = aliases[ra]
      out[(ta,ra)].append(('%.6f' % (p.pcap_secs - timebase),
                           tuple(p.get(i) for i in keys)))
    sessions = list(sorted(out.keys(), key=lambda k: k))
    headers = ['secs']
    data = []
    extra = []
    for sesskey in sessions:
      ta, ra = sesskey
      for k in keys:
        if ta == '~other' and ra == '~other':
          headers.append('other (%s)' % (k,))
        else:
          headers.append('%s to %s (%s)' % (ta, ra, k))
      for secs, values in out[sesskey]:
        data.append([secs] + extra + list(values))
      extra += [None] * len(keys)
    j = json.dumps([headers] + data)
    if self.request.get('jsonp'):
      j = '%s(%s)' % (self.request.get('jsonp'), j)
    self.response.write(j)


def Handle500(req, resp, exc):
  resp.clear()
  resp.headers['Content-type'] = 'text/plain'
  resp.write(traceback.format_exc(exc))
  resp.set_status(500)


settings = dict(
    debug = 1,
)

wsgi_app = webapp2.WSGIApplication([
    (r'/', MainHandler),
    (r'/upload', UploadHandler),
    (r'/download/([^/]+)/[^/]+$', DownloadHandler),
    (r'/view/([^/]+)$', ViewHandler),
    (r'/save/([^/]+)$', SaveHandler),
    (r'/json/([^/]+)$', JsonHandler),
], **settings)

wsgi_app.error_handlers[500] = Handle500
