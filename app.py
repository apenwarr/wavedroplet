#!/usr/bin/env python
import json
import os.path
import random
import re
import sys
import urllib
import wsgiref.handlers
import wsgiref.simple_server
import webapp2
import tornado.template
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
import wifipacket


loader = tornado.template.Loader('.')


class _BaseHandler(webapp2.RequestHandler):
  def render(self, template, **kwargs):
    d = dict()
    d.update(kwargs)
    self.response.write(loader.load(template).generate(**d))


class MainHandler(_BaseHandler):
  def get(self):
    upload_url = blobstore.create_upload_url('/upload')
    self.render('index.html', upload_url=upload_url)


class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
  def post(self):
    upload_files = self.get_uploads()
    sys.stderr.write('upload: %r\n' % upload_files)
    blob_info = upload_files[0]
    self.redirect('/view/%s' % blob_info.key())


class ViewHandler(_BaseHandler):
  def get(self, blobres):
    blobres = str(urllib.unquote(blobres))
    blob_info = blobstore.BlobInfo.get(blobres)
    reader = blob_info.open()
    packets = wifipacket.Packetize(reader)
    self.render('view.html', blob=blob_info, packets=packets)


settings = dict(
    debug = 1,
)

wsgi_app = webapp2.WSGIApplication([
    (r'/', MainHandler),
    (r'/upload', UploadHandler),
    (r'/view/([^/]+)$', ViewHandler),
], **settings)
