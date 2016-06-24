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

"""Support for simple byte queues."""


class Buf(object):
  """A simple auto-sizing byte queue.  Much faster than appending strings."""

  def __init__(self):
    self._buflist = []
    self.used = 0

  def Put(self, b):
    """Add the bytes from b to the end of the buffer."""
    if not b:
      return
    self._buflist.append(b)
    self.used += len(b)

  def _Coagulate(self, want_bytes):
    """Make sure the first element of _buflist is at want_bytes in size."""
    total = 0
    for i, b in enumerate(self._buflist):
      if total >= want_bytes:
        break
      total += len(b)
    else:
      i += 1
    if i > 1:
      self._buflist[0:i] = [''.join(bytes(i) for i in self._buflist[0:i])]

  def Peek(self, n):
    """Retrieve the first n bytes from the buffer, without removing them."""
    if not self.used:
      return ''
    self._Coagulate(n)
    return buffer(self._buflist[0], 0, n)

  def Get(self, n):
    """Retrieve the first n bytes from the buffer, removing them."""
    if not self.used:
      return ''
    self._Coagulate(n)
    ret = buffer(self._buflist[0], 0, n)
    if n < len(self._buflist[0]):
      # don't realloc the bytes; that's slow.  Just wrap them in a view that
      # shows only the bytes we haven't used yet.
      self._buflist[0] = buffer(self._buflist[0], n)
    else:
      self._buflist.pop(0)
    self.used -= len(ret)
    assert self.used or not self._buflist
    return ret

  def GetAll(self):
    """Return all bytes from the buffer, removing them."""
    return self.Get(self.used)

  def Pos(self, char):
    """Return the number of bytes you'd have to Get() to find 'char'."""
    total = 0
    for b in self._buflist:
      p = bytes(b).find(char)
      if p >= 0:
        return total + p + 1
      total += len(b)
    return 0

  def GetUntil(self, char):
    """Get() all the bytes up to and including char. If none, returns ''."""
    return self.Get(self.Pos(char))

  def IsEmpty(self):
    """Returns true if the buffer has no bytes remaining."""
    assert self.used or not self._buflist
    return not self._buflist

  def __repr__(self):
    return 'Buf%r' % ([bytes(i) for i in self._buflist])

  def __str__(self):
    return ''.join(bytes(i) for i in self._buflist)
