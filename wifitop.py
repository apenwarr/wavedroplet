#!/usr/bin/python
import collections
import curses
import os
import select
import subprocess
import time
import wifipacket


RATE_BIN_MAX = 9
RATE_BIN_SHOW_MAX = 7


pcount = None
badcount = None
stations = None


class StationData(object):
  def __init__(self):
    self.packets_tx = [0] * (RATE_BIN_MAX + 1)
    self.packets_rx = [0] * (RATE_BIN_MAX + 1)
    self.rssi = collections.defaultdict(int)
    self.last_type = ''
    self.is_ap = False


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


def _GotPacket(opt, frame):
  global pcount, badcount
  pcount += 1
  if opt.bad:
    badcount += 1
  if opt.typestr[0] != '1':
    if opt.dsmode == 2:
      down = True
      ap_mac, sta_mac = opt.get('ta', None), opt.get('ra', None)
    elif opt.dsmode == 1:
      down = False
      sta_mac, ap_mac = opt.get('ta', None), opt.get('ra', None)
    else:
      # dsmode 0 might be either AP or STA; ignore for now.
      return
    if sta_mac and (int(sta_mac[0:2], 16) & 1):
      sta_mac = 'MCAST'
    if opt.bad and not ap_mac in stations:
      return
    ap_arr = stations[ap_mac]
    ap = ap_arr[None]
    if opt.bad and sta_mac not in ap_arr:
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
    sta.last_type = opt.typestr
    if 'dbm_antsignal' in opt:
      if down:
        ap.rssi[opt.dbm_antsignal] += 1
      else:
        sta.rssi[opt.dbm_antsignal] += 1
    if down and opt.typestr == '08 Beacon':
      ap.is_ap = True


def main(win):
  global stations, pcount, badcount
  pcount = badcount = 0
  stations = collections.defaultdict(lambda: collections.defaultdict(StationData))
  p = subprocess.Popen(['tcpdump', '-Ilni', 'en0', '-w', '-'],
                       stdout=subprocess.PIPE, stderr=open('/dev/null', 'w'))
  streams = []
  streams.append((os.dup(p.stdout.fileno()),
                  wifipacket.Packetizer(_GotPacket)))
  #streams.append((os.open('foo.pcap', os.O_RDONLY),
  #                wifipacket.Packetizer(_GotPacket)))

  last_update = 0
  while 1:
    now = time.time()
    if now - last_update > 0.1:
      rows, cols = win.getmaxyx()
      last_update = now
      win.move(0, 0)
      win.addstr('%-20.20s %4s %6s %8s %6s %8s %s' %
                 ('%d pkt, %d bad' % (pcount, badcount),
                  'RSSI', 'Up', '-----MCS', 'Down', '-----MCS', 'Type'))
      n = -1
      for ap_mac, ap_arr in sorted(stations.iteritems(),
                                   key = lambda (mac,aa): -sum(aa[None].packets_tx)-sum(aa[None].packets_rx)):
        for sta_mac, stats in sorted(ap_arr.iteritems(),
                                     key=lambda (mac,st): -sum(st.packets_tx)-sum(st.packets_rx)):
          n += 1
          if n >= rows - 1:
            break
          rssi_avg = sum(rssi*count for (rssi, count) in stats.rssi.iteritems()) / (1+sum(count for (rssi, count) in stats.rssi.iteritems()))
          is_ap = 0 if sta_mac else 1
          down_packets = stats.packets_tx if is_ap else stats.packets_rx
          up_packets = stats.packets_rx if is_ap else stats.packets_tx
          row = ('%-20s %4s %6d %-8s %6d %-8s %s' %
                 ('   ' + sta_mac if sta_mac else 'AP ' + ap_mac,
                  ('%d' % rssi_avg) if rssi_avg else '',
                  sum(up_packets),
                  RateArt(up_packets, RATE_BIN_SHOW_MAX),
                  sum(down_packets),
                  RateArt(down_packets, RATE_BIN_SHOW_MAX),
                  stats.last_type))
          win.addstr('\n%s' % row[:cols-1])
      win.move(0, 0)
      win.refresh()
    r, w, x = select.select([s for s,_ in streams], [], [], 0.1)
    if r:
      for stream, packetizer in streams[:]:
        if stream in r:
          b = os.read(stream, 65536)
          if b:
            packetizer.Handle(b)
          else:
            # EOF
            streams.remove((stream, packetizer))


if __name__ == '__main__':
  try:
    main(curses.initscr())
  finally:
    curses.endwin()
