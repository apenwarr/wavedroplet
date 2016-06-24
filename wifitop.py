#!/usr/bin/python
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

import collections
import curses
import errno
import os
import re
import select
import subprocess
import sys
import time
import ieee_oui
import wifipacket


RATE_BIN_MAX = 9
RATE_BIN_SHOW_MAX = 7


pcount = None
badcount = None
unknowncount = None
controlcount = None
stations = None
oui = None
aliases = None


class Aliases(object):
  def __init__(self, filename):
    self.filename = filename
    self.file_time = 0
    self.dirty = False
    self.orig_lookup = {}
    self.lookup = {}
    self.Load()

  def Load(self):
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
    try:
      vendor = oui.GetNiceName(mac)
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
    name = '?' + name
    if (mac not in self.orig_lookup or
        self.lookup.get(mac, '').startswith('?')):
      if self.lookup.get(mac) != name:
        self.lookup[mac] = name
        self.dirty = True


class StationData(object):
  def __init__(self):
    self.packets_tx = [0] * (RATE_BIN_MAX + 1)
    self.packets_rx = [0] * (RATE_BIN_MAX + 1)
    self.rssi = collections.defaultdict(int)
    self.last_type = ''
    self.last_updated = 0
    self.is_ap = False
    self.is_expanded = False

  def Zero(self):
    self.packets_tx = [0 for i in self.packets_tx]
    self.packets_rx = [0 for i in self.packets_rx]
    self.last_updated = 0
    self.rssi.clear()


def RateArt(bins, maxbin):
  # To keep the column length smaller, we treat all bins >= maxbin as
  # one big "meh, fast enough" bin.  But we still report the exact bin was
  # the largest in that group.
  fixbins = bins[:maxbin] + [sum(bins[maxbin:])]
  mosti = 0
  most = 1
  for i, v in enumerate(fixbins):
    if v >= most:
      mosti = i
      most = v
  out = []
  for i, v in enumerate(fixbins):
    if not v:
      c = ' '
    elif v >= most:
      if i == maxbin:
        if mosti < i:
          raise AssertionError('mosti(%d) < i(%d) in %r' % (mosti, i, bins))
        c = str(mosti)
      else:
        c = str(i)
    elif v > most / 20:
      c = '*'
    else:
      c = '.'
    out.append(c)
  return ''.join(out)


def _IsMcast(sta_mac):
  return sta_mac and int(sta_mac[0:2], 16) & 1


def _GotPacket(opt, frame):
  global pcount, badcount, unknowncount, controlcount
  pcount += 1
  if opt.bad:
    badcount += 1
  if opt.typestr[0] == '1':
    # control traffic is uninteresting for now
    controlcount += 1
  else:
    if opt.dsmode == 2 or (opt.dsmode == 0 and opt.type == 0x08):
      down = True
      ap_mac, sta_mac = opt.get('ta', None), opt.get('ra', None)
    elif opt.dsmode == 1:
      down = False
      sta_mac, ap_mac = opt.get('ta', None), opt.get('ra', None)
    else:
      # dsmode 0 is unclear whether AP or STA; ignore for now.
      return
    if opt.bad and ap_mac not in stations:
      unknowncount += 1
      return
    ap_arr = stations[ap_mac]
    ap = ap_arr[None]
    if opt.bad and sta_mac not in ap_arr:
      unknowncount += 1
      return
    sta = ap_arr[sta_mac]
    if opt.typestr[0] == '2':  # only care about data rates
      rate_bin = min(opt.get('mcs', 0), RATE_BIN_MAX)
      if down:
        ap.packets_tx[rate_bin] += 1
        sta.packets_rx[rate_bin] += 1
      else:
        ap.packets_rx[rate_bin] += 1
        sta.packets_tx[rate_bin] += 1
    if 'dbm_antsignal' in opt:
      if down:
        ap.rssi[opt.dbm_antsignal] += 1
      else:
        sta.rssi[opt.dbm_antsignal] += 1
    if down and opt.typestr == '08 Beacon':
      ap.is_ap = True
      ssid = opt.get('ssid')
      if ssid:
        ssid = re.sub(r'[^\w]', '.', ssid)
        aliases.BetterGuess(ap_mac, ssid)
    if opt.typestr not in ('08 Beacon', '24 Null'):
      sta.last_updated = ap.last_updated = time.time()
      sta.last_type = ap.last_type = opt.typestr


def _CursesMain(win):
  global oui, stations, aliases, pcount, badcount, unknowncount, controlcount
  pcount = badcount = unknowncount = controlcount = 0
  use_aliases = True
  show_mcast = False
  oui = ieee_oui.OuiTable('oui.txt')
  aliases = Aliases(os.path.expanduser('~/.ether_aliases'))
  stations = collections.defaultdict(lambda: collections.defaultdict(StationData))
  p = subprocess.Popen(['tcpdump', '-Ilni', 'en0', '-w', '-'],
                       stdout=subprocess.PIPE, stderr=open('/dev/null', 'w'))
  streams = []
  streams.append((os.dup(p.stdout.fileno()),
                  wifipacket.Packetizer(_GotPacket)))
  #streams.append((os.open('foo.pcap', os.O_RDONLY),
  #                wifipacket.Packetizer(_GotPacket)))

  last_update = 0
  win.nodelay(True)
  win.notimeout(True)
  win.keypad(True)
  curses.noecho()
  curses.cbreak()
  rows, cols = win.getmaxyx()
  curx = cury = maxrow = 0
  cur_sta = None
  while 1:
    try:
      ch = win.getkey()
    except curses.error:
      pass
    else:
      last_update = 0
      if ch.lower() == 'q':
        break
      elif ch.lower() == 'm':
        show_mcast = not show_mcast
      elif ch.lower() == 'z':
        for ap in stations.values():
          for station in ap.values():
            station.Zero()
        pcount = badcount = 0
      elif ch.lower() == 'n':
        use_aliases = not use_aliases
      elif ch in ('\n', '\r'):
        if cur_sta:
          cur_sta.is_expanded = not cur_sta.is_expanded
      elif ch == 'KEY_DOWN':
        cury += 1
      elif ch == 'KEY_UP':
        cury -= 1
        cury = max(cury, 0)
      elif ch == 'KEY_RIGHT':
        curx += 1
      elif ch == 'KEY_LEFT':
        curx -= 1
        curx = max(curx, 0)
      elif ch in ('KEY_HOME', '\x01'):
        curx = 0
      elif ch in ('KEY_END', '\x05'):
        curx = cols - 1
      elif ch == 'KEY_PPAGE':
        cury = 0
      elif ch == 'KEY_NPAGE':
        cury = rows - 1

    now = time.time()
    if now - last_update > 0.1:
      aliases.Load()
      rows, cols = win.getmaxyx()
      last_update = now
      win.scrollok(False)
      win.addstr(0, 0,
                 '%-21.21s %4s %6s %8s %6s %8s %s' %
                 ('%dkp %dkb %dku %dkc' %
                  (pcount/1000, badcount/1000,
                   unknowncount/1000, controlcount/1000),
                  'RSSI', 'Up', '-----MCS', 'Down', '-----MCS', 'Type'),
                 0)
      n = 0
      for ap_mac, ap_arr in sorted(stations.iteritems(),
                                   key = lambda (mac,aa): -sum(aa[None].packets_tx)-sum(aa[None].packets_rx)):
        ap = ap_arr[None]
        for sta_mac, stats in sorted(ap_arr.iteritems(),
                                     key=lambda (mac,st): (not not mac)-sum(st.packets_tx)-sum(st.packets_rx)):
          rssi_avg = sum(rssi*count for (rssi, count) in stats.rssi.iteritems()) / (1+sum(count for (rssi, count) in stats.rssi.iteritems()))
          is_ap = 0 if sta_mac else 1
          if not is_ap and not ap.is_expanded:
            continue
          down_packets = stats.packets_tx if is_ap else stats.packets_rx
          up_packets = stats.packets_rx if is_ap else stats.packets_tx
          is_mcast = _IsMcast(sta_mac)
          if is_mcast and not show_mcast:
            continue
          if is_mcast:
            typ = '   *'
          elif sta_mac:
            typ = '   '
          else:
            typ = ' AP ' if stats.is_expanded else '+AP '
          mac = sta_mac or ap_mac
          nice_mac = mac
          try:
            nice_mac = aliases.Get(mac)
          except KeyError:
            aliases.Invent(mac)
            nice_mac = aliases.Get(mac)
          row = ('%-4s%-17.17s %4s %6s %-8s %6s %-8s %s' %
                 (typ,
                  nice_mac if use_aliases else mac,
                  ('%d' % rssi_avg) if rssi_avg else '',
                  sum(up_packets) or '',
                  RateArt(up_packets, RATE_BIN_SHOW_MAX),
                  sum(down_packets) or '',
                  RateArt(down_packets, RATE_BIN_SHOW_MAX),
                  stats.last_type))
          try:
            win.addstr(n + 1, 0,
                       '%-*.*s' % (cols, cols, row),
                       curses.A_BOLD
                       if time.time() - stats.last_updated < 2 else 0)
          except curses.error:
            # See http://stackoverflow.com/questions/36387625/curses-calling-addch-on-the-bottom-right-corner
            pass
          if cury == n + 1:
            cur_sta = stats
          if n >= rows - 1:
            break
          n += 1
      maxrow = n
      win.clrtobot()
      cury = min(min(cury, rows - 1), maxrow)
      curx = min(curx, cols - 1)
      win.move(cury, curx)
      win.refresh()
    try:
      r, w, x = select.select([sys.stdin] + [s for s,_ in streams],
                              [], [], 0.1)
    except select.error as e:
      pass
    else:
      if r:
        for stream, packetizer in streams[:]:
          if stream in r:
            b = os.read(stream, 65536)
            if b:
              packetizer.Handle(b)
            else:
              # EOF
              streams.remove((stream, packetizer))


def main():
  try:
    _CursesMain(curses.initscr())
  finally:
    curses.endwin()
    if aliases:
      aliases.Save()


if __name__ == '__main__':
  main()
