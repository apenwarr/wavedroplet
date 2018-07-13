#!/usr/bin/python
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

"""Functions for decoding wifi pcap files."""

from __future__ import print_function
import bz2
import csv
import gzip
import os
import select
import struct
import sys

import mybuf


class Error(Exception):
  pass


class FileError(Error):
  pass


class PacketError(Error):
  pass


class Struct(dict):
  """Helper to allow accessing dict members using this.that notation."""

  def __init__(self, *args, **kwargs):
    dict.__init__(self, *args, **kwargs)
    self.__dict__.update(**kwargs)

  def __getattr__(self, name):
    return self[name]

  def __setattr__(self, name, value):
    self[name] = value

  def __delattr__(self, name):
    del self[name]


GZIP_MAGIC = '\x1f\x8b\x08'
TCPDUMP_MAGIC = 0xa1b2c3d4
TCPDUMP_VERSION = (2, 4)
LINKTYPE_IEEE802_11_RADIOTAP = 127
SHORT_GI_MULT = 10 / 9.

# Basic calculation for Interframe times.
# https://en.wikipedia.org/wiki/DCF_Interframe_Space
#
# TODO(apenwarr): do this more precisely.
#   This is cheating a bit: the interframe spaces somewhat depend on
#   wifi standard in use and which band we're on.  We also don't try to
#   differentiate between different frame types or priority levels.
SIFS_USEC = 16
SLOT_TIME_USEC = 9
IFS_USEC = SIFS_USEC + (2 * SLOT_TIME_USEC)


class Flags(object):
  """Flags in the radiotap header."""
  CFP = 0x01
  SHORT_PREAMBLE = 0x02
  WEP = 0x04
  FRAGMENTATION = 0x08
  FCS = 0x10
  DATA_PAD = 0x20
  BAD_FCS = 0x40
  SHORT_GI = 0x80


RADIOTAP_FIELDS = [
    ('mac_usecs', 'Q'),          # microseconds = timestamp received
    ('flags', 'B'),              # bit field (matches the enum above)
    ('rate', 'B'),               # Mb/s (=speed of the packet) can slow down
    ('channel', 'HH'),           # the channel number on which it was received
    ('fhss', 'BB'),              # ???
    ('dbm_antsignal', 'b'),      # power level of the received signal
    ('dbm_antnoise', 'b'),       # power level of the background noise
    ('lock_quality', 'H'),       # nobody really uses it for anything (NRUIFA)
    ('tx_attenuation', 'H'),     # NRUIFA
    ('db_tx_attenuation', 'B'),  # NRUIFA
    ('dbm_tx_power', 'b'),       # NRUIFA
    ('antenna', 'B'),            # which antenna
    ('db_antsignal', 'B'),       # uncalibrated dbm_*
    ('db_antnoise', 'B'),        # uncalibrated dmb_*
    ('rx_flags', 'H'),           # ???
    ('tx_flags', 'H'),           # ???
    ('rts_retries', 'B'),        # ???
    ('data_retries', 'B'),       # ???
    ('channelplus', 'II'),       # ???
    ('ht', 'BBB'),               # like 'rate' only more (=high transmit rate)
    ('ampdu_status', 'IHBB'),    # ??? MBU
    ('vht', 'HBB4sBBH'),         # like 'ht' only more (=higher transmit rate)
]


_STDFRAME = ('ra', 'ta', 'xa', 'seq')
DOT11_TYPES = {
    # Management
    0x00: ('AssocReq', _STDFRAME),
    0x01: ('AssocResp', _STDFRAME),
    0x02: ('ReassocReq', _STDFRAME),
    0x03: ('ReassocResp', _STDFRAME),
    0x04: ('ProbeReq', _STDFRAME),
    0x05: ('ProbeResp', _STDFRAME),
    0x08: ('Beacon', _STDFRAME),
    0x09: ('ATIM', _STDFRAME),
    0x0a: ('Disassoc', _STDFRAME),
    0x0b: ('Auth', _STDFRAME),
    0x0c: ('Deauth', _STDFRAME),
    0x0d: ('Action', _STDFRAME),

    # Control
    0x16: ('CtlExt', ('ra',)),
    0x18: ('BlockAckReq', ('ra', 'ta')),
    0x19: ('BlockAck', ('ra', 'ta')),
    0x1a: ('PsPoll', ('aid', 'ra', 'ta')),
    0x1b: ('RTS', ('ra', 'ta')),
    0x1c: ('CTS', ('ra',)),
    0x1d: ('ACK', ('ra',)),
    0x1e: ('CongestionFreeEnd', ('ra', 'ta')),
    0x1f: ('CongestionFreeEndAck', ('ra', 'ta')),

    # Data
    0x20: ('Data', _STDFRAME),
    0x21: ('DataCongestionFreeAck', _STDFRAME),
    0x22: ('DataCongestionFreePoll', _STDFRAME),
    0x23: ('DataCongestionFreeAckPoll', _STDFRAME),
    0x24: ('Null', _STDFRAME),
    0x25: ('CongestionFreeAck', _STDFRAME),
    0x26: ('CongestionFreePoll', _STDFRAME),
    0x27: ('CongestionFreeAckPoll', _STDFRAME),
    0x28: ('QosData', _STDFRAME),
    0x29: ('QosDataCongestionFreeAck', _STDFRAME),
    0x2a: ('QosDataCongestionFreePoll', _STDFRAME),
    0x2b: ('QosDataCongestionFreeAckPoll', _STDFRAME),
    0x2c: ('QosNull', _STDFRAME),
    0x2d: ('QosCongestionFreeAck', _STDFRAME),
    0x2e: ('QosCongestionFreePoll', _STDFRAME),
    0x2f: ('QosCongestionFreeAckPoll', _STDFRAME),
}


def Align(i, alignment):
  return i + (alignment - 1) & ~(alignment - 1)


def MacAddr(s):
  return ':'.join(('%02x' % i) for i in struct.unpack('6B', s))


def HexDump(s):
  """Convert a binary array to a printable hexdump."""
  out = ''
  for row in xrange(0, len(s), 16):
    out += '%04x ' % row
    for col in xrange(16):
      if len(s) > row + col:
        out += '%02x ' % ord(s[row + col])
      else:
        out += '   '
      if col == 7:
        out += ' '
    out += ' '
    for col in xrange(16):
      if len(s) > row + col:
        c = s[row + col]
        if len(repr(c)) != 3:  # x -> 'x' and newline -> '\\n'
          c = '.'
        out += c
      else:
        out += ' '
      if col == 7:
        out += ' '
    out += '\n'
  return out


# (modulation_name, coding_rate, data_rate(20M, 40M, 80M, 160M))
# To get the data rate with short guard interval, multiply by SHORT_GI_MULT.
MCS_TABLE = [
    ('BPSK', '1/2', (6.5, 13.5, 29.3, 58.5)),
    ('QPSK', '1/2', (13, 27, 58.5, 117)),
    ('QPSK', '3/4', (19.5, 40.5, 87.8, 175.5)),
    ('16-QAM', '1/2', (26, 54, 117, 234)),
    ('16-QAM', '3/4', (39, 81, 175.5, 351)),
    ('64-QAM', '2/3', (52, 108, 234, 468)),
    ('64-QAM', '3/4', (58.5, 121.5, 263.3, 526.5)),
    ('64-QAM', '5/6', (65, 135, 292.5, 585)),
    # 802.11ac only:
    ('256-QAM', '3/4', (78, 162, 351, 702)),
    ('256-QAM', '5/6', (86.7, 180, 390, 780)),
]


def McsToRate(known, flags, index):
  """Given MCS information for a packet, return the corresponding bitrate."""
  if known & 0x01:
    bw_index = (0, 1, 0, 0)[flags & 0x3]
  else:
    bw_index = 0  # 20 MHz
  if known & 0x04:
    gi = ((flags & 0x04) >> 2)
  else:
    gi = 0
  gi_mult = (SHORT_GI_MULT if gi else 1)
  if known & 0x02:
    mcs = index & 0x07
    nss = ((index & 0x18) >> 3) + 1
  else:
    mcs = 0
    nss = 1
  return bw_index, MCS_TABLE[mcs][2][bw_index] * nss * gi_mult


def _ParseTLV(frame, start, end):
  """Prase tag-length-value fields from frame data."""
  d = {}
  ofs = start
  while ofs + 1 < end:
    tag = frame[ofs]
    length = ord(frame[ofs+1])
    if end - ofs - 2 < length:
      # not enough bytes left
      break
    value = frame[ofs+2:ofs+2+length]
    ofs += 2 + length
    d[ord(tag)] = value
  return d


def PacketizeBuf(buf):
  """Given a file containing pcap data, yield a series of packets."""
  while buf.used < 4:
    yield
  magicbytes = buf.Get(4)

  # pcap global header
  if struct.unpack('<I', magicbytes) == (TCPDUMP_MAGIC,):
    byteorder = '<'
  elif struct.unpack('>I', magicbytes) == (TCPDUMP_MAGIC,):
    byteorder = '>'
  else:
    raise FileError('unexpected tcpdump magic %r' % bytes(magicbytes))
  while buf.used < 20:
    yield
  (version_major, version_minor,
   unused_thiszone,
   unused_sigfigs,
   snaplen,
   network) = struct.unpack(byteorder + 'HHiIII', buf.Get(20))
  version = (version_major, version_minor)
  if version != TCPDUMP_VERSION:
    raise FileError('unexpected tcpdump version %r' % version)
  if network != LINKTYPE_IEEE802_11_RADIOTAP:
    raise FileError('unexpected tcpdump network type %r' % network)

  last_ta = None
  last_ra = None
  last_mac_usecs = 0

  while 1:
    opt = Struct({})

    # pcap packet header
    while buf.used < 16:
      yield
    pcaphdr = buf.Get(16)

    (ts_sec, ts_usec,
     incl_len, orig_len) = struct.unpack(byteorder + 'IIII', pcaphdr)
    if incl_len > orig_len:
      raise FileError('packet incl_len(%d) > orig_len(%d): invalid'
                      % (incl_len, orig_len))
    if incl_len > snaplen:
      raise FileError('packet incl_len(%d) > snaplen(%d): invalid'
                      % (incl_len, snaplen))

    opt.pcap_secs = ts_sec + (ts_usec / 1e6)

    # pcap packet data
    while buf.used < incl_len:
      yield
    radiotap = buf.Get(incl_len)
    assert len(radiotap) == incl_len

    opt.incl_len = incl_len
    opt.orig_len = orig_len

    # radiotap header (always little-endian)
    (it_version, unused_it_pad,
     it_len, it_present) = struct.unpack('<BBHI', radiotap[:8])
    if it_version != 0:
      raise PacketError('unknown radiotap version %d' % it_version)
    # handle multiple it_present
    it_presents = []
    it_presents.append(it_present)
    offset = 8
    while it_present & (1 << 31):
      it_present = struct.unpack('<I', radiotap[offset:offset+4])[0]
      it_presents.append(it_present)
      offset += 4
    # choose first flags
    it_present = it_presents[0]

    frame = radiotap[it_len:]
    optbytes = radiotap[offset:it_len]

    ofs = 0
    for i, (name, structformat) in enumerate(RADIOTAP_FIELDS):
      if it_present & (1 << i):
        ofs = Align(ofs, struct.calcsize(structformat[0]))
        sz = struct.calcsize(structformat)
        v = struct.unpack(structformat, optbytes[ofs:ofs + sz])
        if name == 'mac_usecs':
          opt.mac_usecs = v[0]
        elif name == 'channel':
          opt.freq = v[0]
          opt.channel_flags = v[1]
        elif name == 'rate':
          opt.rate = v[0] / 2.  # convert multiples of 500 kb/sec -> Mb/sec
        elif name == 'ht':
          ht_known, ht_flags, ht_index = v
          opt.ht = v
          opt.mcs = ht_index & 0x07
          opt.spatialstreams = 1 + ((ht_index & 0x18) >> 3)
          width, opt.rate = McsToRate(ht_known, ht_flags, ht_index)
          opt.bw = 20 << width
        elif name == 'vht':
          (vht_known, vht_flags, vht_bw, vht_mcs_nss,
           vhd_coding, vht_group_id, vht_partial_aid) = v
          vmn = ord(vht_mcs_nss[0])
          opt.mcs = (vmn & 0xf0) >> 4
          opt.spatialstreams = vmn & 0x0f
          if vht_bw == 0:
            width = 0
          elif vht_bw < 4:
            width = 1
          elif vht_bw < 11:
            width = 2
          else:
            width = 3
          opt.bw = 20 << width
          gi = (vht_flags & 0x04)
          gi_mult = (SHORT_GI_MULT if gi else 1)
          opt.rate = (MCS_TABLE[opt.mcs][2][width]
                      * opt.spatialstreams * gi_mult)
        else:
          opt[name] = v if len(v) > 1 else v[0]
        ofs += sz

    if 'mac_usecs' in opt and 'rate' in opt:
      # TODO(apenwarr): use something smarter than orig_len for byte count.
      #   This includes radiotap header bytes, which is wrong, but probably
      #   leaves out some other stuff, so it sort of averages out to be right,
      #   which isn't really what we want :)
      opt.airtime_usec = opt.orig_len * 8 / opt.rate
      if opt.mac_usecs != last_mac_usecs:
        # Only count the inter-frame time for the first packet in an aggregate
        # (assuming all subframes of an aggregate have the same MAC timestamp)
        opt.airtime_usec += IFS_USEC

    try:
      (fctl, duration) = struct.unpack('<HH', frame[0:4])
    except struct.error:
      (fctl, duration) = 0, 0
    dot11ver = fctl & 0x0003
    dot11type = (fctl & 0x000c) >> 2
    dot11subtype = (fctl & 0x00f0) >> 4
    dot11dsmode = (fctl & 0x0300) >> 8
    dot11morefrag = (fctl & 0x0400) >> 10
    dot11retry = (fctl & 0x0800) >> 11
    dot11powerman = (fctl & 0x1000) >> 12
    dot11moredata = (fctl & 0x2000) >> 13
    dot11wep = (fctl & 0x4000) >> 14
    dot11order = (fctl & 0x8000) >> 15
    fulltype = (dot11type << 4) | dot11subtype
    opt.type = fulltype
    opt.duration = duration
    (typename, typefields) = DOT11_TYPES.get(fulltype, ('Unknown', ('ra',)))
    opt.typestr = '%02X %s' % (fulltype, typename)
    opt.dsmode = dot11dsmode
    opt.retry = dot11retry
    opt.powerman = dot11powerman
    opt.order = dot11order

    ofs = 4
    for i, fieldname in enumerate(typefields):
      if fieldname == 'seq':
        if len(frame) < ofs + 2:
          break
        seq = struct.unpack('<H', frame[ofs:ofs + 2])[0]
        opt.seq = (seq & 0xfff0) >> 4
        opt.frag = (seq & 0x000f)
        ofs += 2
      else:  # ta, ra, xa
        if len(frame) < ofs + 6:
          break
        opt[fieldname] = MacAddr(frame[ofs:ofs + 6])
        ofs += 6

    # Parse extra tags out of some management frames, when possible.
    if opt.type == 0x08:  # Beacon
      ofs += 12  # fixed parameters
      opt.tags = _ParseTLV(frame, ofs, len(frame) - 4)
      opt.ssid = opt.tags.get(0)
      if opt.ssid == '\x00':  # hidden ssid
        del opt.ssid

    # ACK and CTS packets omit TA field for efficiency, so we have to fill
    # it in from the previous packet's RA field.  We can check that the
    # new packet's RA == the previous packet's TA, just to make sure we're
    # not lying about it.
    if opt.get('flags', Flags.BAD_FCS) & Flags.BAD_FCS:
      opt.bad = 1
    else:
      opt.bad = 0
    if not opt.get('ta'):
      if (last_ta and last_ra
          and last_ta == opt.get('ra')
          and last_ra != opt.get('ra')):
        opt['ta'] = last_ra
      last_ta = None
      last_ra = None
    else:
      last_ta = opt.get('ta')
      last_ra = opt.get('ra')
    if 'mac_usecs' in opt:
      last_mac_usecs = opt.mac_usecs

    yield opt, frame


def Packetize(stream, iter_timeout=None):
  """Given a python data stream, yield a series of parsed packets."""
  buf = mybuf.Buf()
  magicbytes = stream.read(4)
  if magicbytes[:len(GZIP_MAGIC)] == GZIP_MAGIC:
    stream.seek(-4, os.SEEK_CUR)
    stream = gzip.GzipFile(mode='rb', fileobj=stream)
  else:
    buf.Put(magicbytes)

  it = PacketizeBuf(buf)
  while 1:
    while 1:
      result = next(it)
      if result:
        yield result
      else:
        # not enough data in buffer
        break
    b = stream.read(4096)
    if not b:
      # EOF
      break
    buf.Put(b)


class Packetizer(object):

  def __init__(self, callback):
    self.buf = mybuf.Buf()
    self.callback = callback
    self.it = PacketizeBuf(self.buf)

  def Handle(self, newbytes):
    self.buf.Put(newbytes)
    while 1:
      result = next(self.it)
      if result:
        opt, frame = result
        self.callback(opt, frame)
      else:
        # not enough data in buffer
        break


def Example(p):
  if 0:
    basetime = 0
    for opt, frame in Packetize(p):
      ts = opt.pcap_secs
      if basetime:
        ts -= basetime
      else:
        basetime = ts
        ts = 0
      print (ts, opt)
#      print HexDump(frame)
  elif 0:
    want_fields = [
        'ta',
        'ra',
        #        'xa',
        #        'freq',
        'seq',
        'mcs',
        'rate',
        'retry',
        'dbm_antsignal',
        'dbm_antnoise',
        #        'frag',
        'typestr',
        #        'powerman',
        #        'order',
        #        'dsmode',
    ]
    co = csv.writer(sys.stdout)
    co.writerow(['pcap_secs'] + want_fields)
    tbase_pcap = 0
    tbase_mac = 0
    for opt, frame in Packetize(p):
      t_pcap = opt.get('pcap_secs', 0)
      if not tbase_pcap: tbase_pcap = t_pcap
      co.writerow(['%.6f' % (t_pcap - tbase_pcap)] +
                  [opt.get(f, None) for f in want_fields])
  else:
    for i, (opt, frame) in enumerate(Packetize(p)):
      ts = opt.pcap_secs
      ts = '%.09f' % ts
      if 'xa' in opt:
        src = opt.xa
      else:
        src = 'no:xa:00:00:00:00'
      if 'mac_usecs' in opt:
        mac_usecs = opt.mac_usecs
      else:
        mac_usecs = 0
      if 'seq' in opt:
        seq = opt.seq
      else:
        seq = 'noseq'
      if 'flags' in opt:
        if opt.flags & Flags.BAD_FCS:
          continue
      print(i + 1,
            src, 'ta=%s' % opt.get('ta'), 'ra=%s' % opt.get('ra'),
            opt.dsmode, opt.typestr, ts,
            opt.rate, 'mcs=%r' % opt.get('mcs'), opt.get('spatialstreams'),
            mac_usecs, opt.orig_len, seq, opt.get('flags'))
      sys.stdout.flush()


def ZOpen(fn):
  if fn.endswith('.bz2'):
    return bz2.BZ2File(fn)
  return open(fn)


if __name__ == '__main__':
  Example(ZOpen(sys.argv[1]))
