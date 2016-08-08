# Copyright 2016 Google Inc. All Rights Reserved.
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

"""Support functions for handling the IEEE OUI database."""

import os
import re


class OuiTable(object):
  """A table mapping ethernet MAC OUI prefixes to vendor names."""

  def __init__(self, filename):
    self.lookup = {}
    for line in open(filename):
      g = re.match(r'(\w\w)(\w\w)(\w\w)\s+\([^)]+\)\s+(.*)', line)
      if g:
        prefix = ('%s:%s:%s:' % (g.group(1), g.group(2), g.group(3))).lower()
        name = g.group(4)
        self.lookup[prefix] = name

  def GetName(self, macaddr):
    return self.lookup[macaddr[:9].lower()]

  def GetNiceName(self, macaddr):
    name = self.GetName(macaddr)
    firstword = name.split()[0]
    return re.sub(r'[^A-Za-z]', '', firstword)[:8]


class Aliases(object):
  """A registry mapping MAC addresses to friendly names."""

  def __init__(self, filename, oui):
    self.filename = filename
    self.oui = oui
    self.file_time = 0
    self.dirty = False
    self.orig_lookup = {}
    self.lookup = {}
    self.Load()

  def Load(self):
    """Update the alias list from any changes in the backing file."""
    try:
      mtime = os.stat(self.filename).st_mtime
    except OSError:
      return  # no file, nothing to do
    if mtime == self.file_time:
      return  # file unchanged, nothing to do

    new_lookup = {}
    f = open(self.filename)
    for line in f:
      t = line.split()[:2]
      if len(t) > 1:
        macaddr, alias = t[:2]
        new_lookup[macaddr.lower()] = alias

    # apply deletions from old to new
    deleted = set(self.orig_lookup.keys()) - set(new_lookup.keys())
    for k in deleted:
      try:
        del self.lookup[k]
      except KeyError:
        pass

    # apply changes/additions from old to new
    changed = set(new_lookup.items()) - set(self.orig_lookup.items())
    for k, v in changed:
      self.lookup[k] = v

    self.file_time = mtime

  def Save(self):
    """If any changes to aliases, rewrite the backing file."""
    if self.dirty:
      self.Load()  # first merge in other people's changes
      f = open(self.filename + '.tmp', 'w')
      for macaddr, alias in sorted(self.lookup.iteritems()):
        if macaddr != alias:
          f.write('%s %s\n' % (macaddr, alias))
      self.file_time = os.fstat(f.fileno()).st_mtime
      self.orig_lookup = dict(self.lookup)
      f.close()
      os.rename(self.filename + '.tmp', self.filename)
      self.dirty = False

  def Get(self, mac):
    n = self.lookup[mac]
    if n.startswith('?'):
      return n[1:]  # ?-indicator is for "guessed" names; don't display
    return n

  def Invent(self, mac):
    """Given a MAC address, try to populate the alias for it if missing."""
    try:
      vendor = self.oui.GetNiceName(mac)
    except KeyError:
      vendor = 'Unknown'
    alias_set = set(self.lookup.values())
    for i in range(1, 1000):
      nice_mac = '?%s%d' % (vendor, i)
      if nice_mac not in alias_set:
        break
    else:
      nice_mac = mac  # too many, give up
    self.lookup[mac] = nice_mac
    self.dirty = True

  def BetterGuess(self, mac, name):
    """If you have a better alias for a given MAC, substitute it."""
    name = '?' + name
    if (mac not in self.orig_lookup or
        self.lookup.get(mac, '').startswith('?')):
      if self.lookup.get(mac) != name:
        self.lookup[mac] = name
        self.dirty = True
