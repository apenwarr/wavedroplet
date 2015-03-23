# Copyright 2014 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Handlers for uploading, filtering, and visualization."""

import collections
import errno
import json
import sys
import time
import traceback
import urllib
import webapp2
import tornado.template
import wifipacket
from google.appengine.api import memcache
from google.appengine.api import users
from google.appengine.ext import blobstore
from google.appengine.ext import ndb
from google.appengine.ext.webapp import blobstore_handlers

BROADCAST = 'ff:ff:ff:ff:ff:ff'
DEFAULT_FIELDS = ['seq', 'rate']
AVAIL_FIELDS = ['seq', 'mcs', 'spatialstreams', 'bw', 'rate', 'retry',
                'type', 'typestr', 'dbm_antsignal', 'dbm_antnoise',
                'bad']

IS_DEBUG = False
SAMPLE_SIZE = 2

loader = tornado.template.Loader('.')


def _Esc(s):
  """Like tornado.escape.url_escape, but only escapes &, #, %, and =."""
  out = []
  for c in s:
    if c in ['&', '#', '%', '=']:
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
  """Enforcing @google.com login."""

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
  """Info about pcap file and its visualization settings/cache."""

  create_time = ndb.DateTimeProperty(auto_now_add=True)
  create_user_email = ndb.StringProperty()
  filename = ndb.StringProperty()
  show_hosts = ndb.StringProperty(repeated=True)
  show_fields = ndb.StringProperty(repeated=True)
  aliases = ndb.PickleProperty()

  # Cached JSON representations for various useful subsets of data
  # to be passed to the JS side for visualization.
  # All captured packets
  js_packets = ndb.JsonProperty(compressed=True)
  # All pairs of (transmitter, receiver)
  js_streams = ndb.JsonProperty(compressed=True)

  @staticmethod
  def GetDefault():
    return PcapData.get_or_insert(str('*'), show_hosts=[], aliases={})

  @staticmethod
  def GetOrInsertFromBlob(blob_info):
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
  """Re-/store from/to memcache number of packets per mac address."""

  boxes = memcache.get(str(blob_info.key()), namespace='boxes')
  if not boxes:
    reader = blob_info.open()
    boxes = collections.defaultdict(lambda: 0)
    # TODO(katepek): use cache here instead if available
    for p, unused_frame in wifipacket.Packetize(reader):
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
    capdefault = PcapData.GetDefault()
    pcapdata = PcapData.GetOrInsertFromBlob(blob_info)

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
    capdefault = PcapData.GetDefault()
    u = users.get_current_user()
    if u:
      email = u.email()
    else:
      email = 'anonymous'
    sys.stderr.write('stupid user:%r email:%r\n' % (u, email))
    pcapdata = PcapData.GetOrInsertFromBlob(blob_info)
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

    _MaybeCache('on' == self.request.get('update-cache'),
                blob_info, pcapdata)

    capdefault.put()
    pcapdata.put()

    self.redirect('/d3viz.html?key=%s&to_plot=%s'
                  % (_Esc(str(blob_info.key())),
                     _Esc(','.join(pcapdata.show_fields))))


def _MaybeCache(update_cache, blob_info, pcapdata):
  """Update cache when asked to do so. Cache when no cache found."""

  if update_cache:
    pcapdata.js_packets = None
    pcapdata.js_streams = None

  if pcapdata.js_packets is not None:
    print "We just used cache, didn't we"
    return

  reader = blob_info.open()
  begin = time.time()

  j = []
  pairs = set()
  for i, (p, unused_frame) in enumerate(wifipacket.Packetize(reader)):
    if IS_DEBUG and i > SAMPLE_SIZE:
      print 'Done', i
      break
    j.append(p)
    pairs.add((p.get('ta', 'no_ta'), p.get('ra', 'no_ra')))

  pairs_dict = [{'ta': t[0], 'ra': t[1]} for t in pairs]

  pcapdata.js_packets = json.dumps(j)
  pcapdata.js_streams = json.dumps(pairs_dict)

  end = time.time()
  print 'Spent on caching', (end - begin), 'sec'


class JsonHandler(_BaseHandler):

  @GoogleLoginRequired
  def get(self, blobres):
    blob_info = blobstore.BlobInfo.get(str(urllib.unquote(blobres)))
    pcapdata = PcapData.GetOrInsertFromBlob(blob_info)

    self.response.headers['Content-Type'] = 'application/json'
    # include in js_bundle any content to be included in json being passed to index.html
    js_bundle = {
        'js_packets': pcapdata.js_packets,
        'js_streams': pcapdata.js_streams,
    }
    self.response.out.write(json.dumps(js_bundle))


def Handle500(unused_req, resp, exc):
  resp.clear()
  resp.headers['Content-type'] = 'text/plain'
  resp.write(traceback.format_exc(exc))
  resp.set_status(500)


settings = dict(
    debug=1,
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
