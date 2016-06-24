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


if __name__ == '__main__':
  o = OuiTable('oui.txt')
  mac = 'A4:29:83:11:22:33'
  print '%r %r' % (o.GetName(mac), o.GetNiceName(mac))
