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

"""A vmstat-like tool for showing periodic wifi airtime usage."""

import os
import re
import string
import sys
import ieee_oui
import wifipacket

USEC_PER_ROW = 1024000 / 2
USEC_PER_COL = int(USEC_PER_ROW / 64)
USEC_PER_ROW = USEC_PER_COL * 64  # fix any rounding errors


def _main(aliases):
  """Main program."""
  last_usec = row_start_usec = col_start_usec = rownum = colnum = 0
  row_airtime = col_airtime = time_init = 0
  col_packets = []
  row_macs = set()
  real_macs = set()
  abbrevs = {}
  abbrev_queue = list(reversed(string.ascii_uppercase))

  for opt, unused_frame in wifipacket.Packetize(sys.stdin):
    # TODO(apenwarr): handle control frame timing more carefully
    if opt.type & 0xf0 == 0x10:
      continue

    col_packets.append(opt)
    col_airtime += opt.get('airtime_usec', 0)
    row_airtime += opt.get('airtime_usec', 0)
    ta = opt.get('ta', '???')
    ts = opt.pcap_secs
    ts = '%.09f' % ts
    mac_usecs = opt.get('mac_usecs', last_usec)
    assert mac_usecs
    tsdiff = mac_usecs - last_usec
    bad_fcs = opt.get('flags', 0) & wifipacket.Flags.BAD_FCS
    if not bad_fcs:
      row_macs.add(ta)
      real_macs.add(ta)

    if not bad_fcs and opt.type == 0x08:  # beacon
      ssid = opt.get('ssid')
      if ssid:
        ssid = re.sub(r'[^\w]', '.', ssid)
        aliases.BetterGuess(ta, ssid)

    if not time_init:
      col_start_usec = row_start_usec = mac_usecs
      time_init = 1

    # TODO(apenwarr): deal with mac_usecs wraparound
    while mac_usecs - col_start_usec >= USEC_PER_COL:
      if col_start_usec - row_start_usec >= USEC_PER_ROW:
        print ' %2d%%' % (row_airtime * 100 / USEC_PER_ROW)  # end of row
        if (rownum % 20) == 0:
          print
          print '--- .=Beacon ',
          for mac in row_macs:
            nice_mac = aliases.Get(mac)
            abbrev = abbrevs.get(mac, '')
            print '%s=%s' % (abbrev, nice_mac),
          print
          row_macs.clear()
        rownum += 1
        colnum = 0
        row_start_usec += USEC_PER_ROW
        row_airtime = 0

      most_airtime = 0, None, 0
      for p in col_packets:
        ta = p.get('ta', '???')
        airtime = p.get('airtime_usec', 0)
        if ta in real_macs and airtime > most_airtime[0]:
          most_airtime = airtime, ta, p.type
      if not most_airtime[1]:
        c = ' '
      elif most_airtime[1] in abbrevs:
        c = abbrevs[most_airtime[1]]
      else:
        mac = most_airtime[1]
        try:
          nice_mac = aliases.Get(mac)
        except KeyError:
          aliases.Invent(mac)
          nice_mac = aliases.Get(mac)
        c = nice_mac[0].upper()  # try first letter of vendor or SSID
        if c in abbrevs.values():
          # Fallback in case that's already taken
          c = abbrev_queue.pop(0)
          abbrev_queue.append(c)
        abbrevs[most_airtime[1]] = c
      if most_airtime[2] == 0x08:   # override if beacon was the biggest thing
        c = '.'
      if col_airtime < USEC_PER_COL / 2:
        c = c.lower()
      sys.stdout.write(c)
      col_start_usec += USEC_PER_COL
      col_airtime = 0
      col_packets = []
      colnum += 1

    if 0:  # pylint: disable=using-constant-test
      print '%-20s %7dM %9db %11s +%-9.3f  %s' % (
          nice_mac,
          opt.rate, opt.orig_len,
          '%.3fms' % (tsdiff/1e3) if tsdiff else '',
          opt.airtime_usec / 1e3,
          opt.typestr,
      )
    sys.stdout.flush()
    last_usec = mac_usecs


def main():
  oui = ieee_oui.OuiTable('oui.txt')
  aliases = ieee_oui.Aliases(os.path.expanduser('~/.ether_aliases'), oui)
  try:
    _main(aliases)
  finally:
    aliases.Save()


if __name__ == '__main__':
  main()
