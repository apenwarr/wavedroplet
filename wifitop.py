#!/usr/bin/python
import collections
import curses
import os
import select
import subprocess
import time
import wifipacket


ASCII_ART = ' .:-=+*#%@'


class StationData(object):
  def __init__(self):
    self.packets_tx = collections.defaultdict(int)
    self.packets_rx = collections.defaultdict(int)
    self.bytes_tx = collections.defaultdict(int)
    self.bytes_rx = collections.defaultdict(int)
    self.rssi = collections.defaultdict(int)
    self.last_type = ''
    self.is_ap = False


def RateArt(bins):
  total = sum(bins.values()) + 1
  if bins:
    most = max(max(bins.values()), 1)
  else:
    most = -1
  out = []
  for i in range(10): # range(0, 100, 10):
    #out.append(ASCII_ART[min(9, 10 * bins[i] / total)])
    v = bins[i]
    if v == most:
      out.append(str(i))#'*')
    elif v > 0:
      out.append('.')
    else:
      out.append(' ')
  return ''.join(out)


def main(win):
  rows, cols = win.getmaxyx()
  stations = collections.defaultdict(lambda: collections.defaultdict(StationData))
  p = subprocess.Popen(['tcpdump', '-Ilni', 'en0', '-w', '-'],
                       stdout=subprocess.PIPE, stderr=open('/dev/null', 'w'))
  stream = os.dup(p.stdout.fileno())
  packets = wifipacket.Packetize(os.fdopen(stream, 'r', 0))
  packeti = iter(packets)
  pcount = 0
  next_timeout = 0
  last_update = 0
  while 1:
    #if next_timeout:   # FIXME broken
    now = time.time()
    if now - last_update > 0.5:
      last_update = now
      win.move(0, 0)
      win.addstr('%-20s %5s %6s %-10s %6s %-10s %s\n' %
                 ('%d pkts, nto=%d' % (pcount, next_timeout),
                  'RSSI', 'Up', '', 'Down', '', 'Type'))
      n = -1
      for ap_mac, ap_arr in sorted(stations.iteritems(),
                                   key = lambda (mac,aa): -sum(aa[None].packets_tx.values())-sum(aa[None].packets_rx.values())):
        for sta_mac, stats in sorted(ap_arr.iteritems(),
                                     key=lambda (mac,st): -sum(st.packets_tx.values())-sum(st.packets_rx.values())):
          n += 1
          if n >= rows - 2:
            break
          rssi_avg = sum(rssi*count for (rssi, count) in stats.rssi.iteritems()) / (1+sum(count for (rssi, count) in stats.rssi.iteritems()))
          is_ap = 0 if sta_mac else 1
          row = ('%-20s %5s %6d %10s %6d %10s %s' %
                 ('   ' + sta_mac if sta_mac else 'AP ' + ap_mac,
                  ('%ddB' % rssi_avg) if rssi_avg else '',
                  sum(stats.packets_tx.values()),
                  '' if is_ap else RateArt(stats.packets_tx),
                  sum(stats.packets_rx.values()),
                  '' if is_ap else RateArt(stats.packets_rx),
                  stats.last_type))
          win.addstr('%s\n' % row[:cols-1])
      win.refresh()
    r, w, x = select.select([stream], [], [], next_timeout)
    if r:
      opt, frame = next(packeti)
      pcount += 1
      if opt.typestr[0] != '1':
        if opt.dsmode == 2:
          down = True
          ap_mac, sta_mac = opt.get('ta', None), opt.get('ra', None)
        elif opt.dsmode == 1:
          down = False
          sta_mac, ap_mac = opt.get('ta', None), opt.get('ra', None)
        else:
          # dsmode 0 might be either AP or STA; ignore for now.
          continue
        if sta_mac and (int(sta_mac[0:2], 16) & 1):
          sta_mac = 'MCAST'
        if opt.bad and not ap_mac in stations:
          continue
        ap_arr = stations[ap_mac]
        ap = ap_arr[None]
        if opt.bad and sta_mac not in ap_arr:
          continue
        sta = ap_arr[sta_mac]
        if opt.typestr[0] == '2':  # only care about data rates
          rate_bin = min(opt.get('mcs', 0), 9) # min(90, int(opt.get('rate', 0) / 10) * 10)
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
      next_timeout = 0
    else:
      next_timeout = 0.1


if __name__ == '__main__':
  try:
    main(curses.initscr())
  finally:
    curses.endwin()
