#!/usr/bin/env python2
"""Functions for decoding wifi pcap files."""

from __future__ import print_function
import bz2
import csv
import gzip
import os
import struct
import sys


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
    ('mac_usecs', 'Q'),
    ('flags', 'B'),
    ('rate', 'B'),
    ('channel', 'HH'),
    ('fhss', 'BB'),
    ('dbm_antsignal', 'b'),
    ('dbm_antnoise', 'b'),
    ('lock_quality', 'H'),
    ('tx_attenuation', 'H'),
    ('db_tx_attenuation', 'B'),
    ('dbm_tx_power', 'b'),
    ('antenna', 'B'),
    ('db_antsignal', 'B'),
    ('db_antnoise', 'B'),
    ('rx_flags', 'H'),
    ('tx_flags', 'H'),
    ('rts_retries', 'B'),
    ('data_retries', 'B'),
    ('channelplus', 'II'),
    ('ht', 'BBB'),
    ('ampdu_status', 'IHBB'),
    ('vht', 'HBB4sBBH'),
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


MCS_TABLE = [
    (1, 'BPSK', '1/2', (6.50, 7.20, 13.50, 15.00)),
    (1, 'QPSK', '1/2', (13.00, 14.40, 27.00, 30.00)),
    (1, 'QPSK', '3/4', (19.50, 21.70, 40.50, 45.00)),
    (1, '16-QAM', '1/2', (26.00, 28.90, 54.00, 60.00)),
    (1, '16-QAM', '3/4', (39.00, 43.30, 81.00, 90.00)),
    (1, '64-QAM', '2/3', (52.00, 57.80, 108.00, 120.00)),
    (1, '64-QAM', '3/4', (58.50, 65.00, 121.50, 135.00)),
    (1, '64-QAM', '5/6', (65.00, 72.20, 135.00, 150.00)),
    (2, 'BPSK', '1/2', (13.00, 14.40, 27.00, 30.00)),
    (2, 'QPSK', '1/2', (26.00, 28.90, 54.00, 60.00)),
    (2, 'QPSK', '3/4', (39.00, 43.30, 81.00, 90.00)),
    (2, '16-QAM', '1/2', (52.00, 57.80, 108.00, 120.00)),
    (2, '16-QAM', '3/4', (78.00, 86.70, 162.00, 180.00)),
    (2, '64-QAM', '2/3', (104.00, 115.60, 216.00, 240.00)),
    (2, '64-QAM', '3/4', (117.00, 130.00, 243.00, 270.00)),
    (2, '64-QAM', '5/6', (130.00, 144.40, 270.00, 300.00)),
    (3, 'BPSK', '1/2', (19.50, 21.70, 40.50, 45.00)),
    (3, 'QPSK', '1/2', (39.00, 43.30, 81.00, 90.00)),
    (3, 'QPSK', '3/4', (58.50, 65.00, 121.50, 135.00)),
    (3, '16-QAM', '1/2', (78.00, 86.70, 162.00, 180.00)),
    (3, '16-QAM', '3/4', (117.00, 130.00, 243.00, 270.00)),
    (3, '64-QAM', '2/3', (156.00, 173.30, 324.00, 360.00)),
    (3, '64-QAM', '3/4', (175.50, 195.00, 364.50, 405.00)),
    (3, '64-QAM', '5/6', (195.00, 216.70, 405.00, 450.00)),
    (4, 'BPSK', '1/2', (26.00, 28.80, 54.00, 60.00)),
    (4, 'QPSK', '1/2', (52.00, 57.60, 108.00, 120.00)),
    (4, 'QPSK', '3/4', (78.00, 86.80, 162.00, 180.00)),
    (4, '16-QAM', '1/2', (104.00, 115.60, 216.00, 240.00)),
    (4, '16-QAM', '3/4', (156.00, 173.20, 324.00, 360.00)),
    (4, '64-QAM', '2/3', (208.00, 231.20, 432.00, 480.00)),
    (4, '64-QAM', '3/4', (234.00, 260.00, 486.00, 540.00)),
    (4, '64-QAM', '5/6', (260.00, 288.80, 540.00, 600.00)),
    (1, 'BPSK', '1/2', (0, 0, 6.50, 7.20)),
]


def McsToRate(known, flags, index):
  """Given MCS information for a packet, return the corresponding bitrate."""
  if known & (1 << 0):
    bw = (20, 40, 20, 20)[flags & 0x3]
  else:
    bw = 20
  if known & (1 << 2):
    gi = ((flags & 0x4) >> 2)
  else:
    gi = 0
  if known & (1 << 1):
    mcs = index
  else:
    mcs = 0
  if bw == 20:
    si = 0
  else:
    si = 2
  if gi:
    si += 1
  return MCS_TABLE[mcs][3][si]


def Packetize(stream):
  """Given a file containing pcap data, yield a series of packets."""
  magicbytes = stream.read(4)

  if magicbytes[:len(GZIP_MAGIC)] == GZIP_MAGIC:
    stream.seek(-4, os.SEEK_CUR)
    stream = gzip.GzipFile(mode='rb', fileobj=stream)
    magicbytes = stream.read(4)

  # pcap global header
  if struct.unpack('<I', magicbytes) == (TCPDUMP_MAGIC,):
    byteorder = '<'
  elif struct.unpack('>I', magicbytes) == (TCPDUMP_MAGIC,):
    byteorder = '>'
  else:
    raise FileError('unexpected tcpdump magic %r' % magicbytes)
  (version_major, version_minor,
   unused_thiszone,
   unused_sigfigs,
   snaplen,
   network) = struct.unpack(byteorder + 'HHiIII', stream.read(20))
  version = (version_major, version_minor)
  if version != TCPDUMP_VERSION:
    raise FileError('unexpected tcpdump version %r' % version)
  if network != LINKTYPE_IEEE802_11_RADIOTAP:
    raise FileError('unexpected tcpdump network type %r' % network)

  last_ta = None
  last_ra = None
  while 1:
    opt = Struct({})

    # pcap packet header
    pcaphdr = stream.read(16)
    if len(pcaphdr) < 16: break  # EOF
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
    radiotap = stream.read(incl_len)
    if len(radiotap) < incl_len: break  # EOF

    opt.incl_len = incl_len
    opt.orig_len = orig_len

    # radiotap header (always little-endian)
    (it_version, unused_it_pad,
     it_len, it_present) = struct.unpack('<BBHI', radiotap[:8])
    if it_version != 0:
      raise PacketError('unknown radiotap version %d' % it_version)
    frame = radiotap[it_len:]
    optbytes = radiotap[8:it_len]

    ofs = 0
    for i, (name, structformat) in enumerate(RADIOTAP_FIELDS):
      if it_present & (1 << i):
        ofs = Align(ofs, struct.calcsize(structformat[0]))
        sz = struct.calcsize(structformat)
        v = struct.unpack(structformat, optbytes[ofs:ofs + sz])
        if name == 'mac_usecs':
          opt.mac_usecs = v[0]
          # opt.mac_secs = v[0] / 1e6
        elif name == 'channel':
          opt.freq = v[0]
          opt.channel_flags = v[1]
        elif name == 'ht':
          ht_known, ht_flags, ht_index = v
          opt.ht = v
          opt.mcs = ht_index
          opt.rate = McsToRate(ht_known, ht_flags, ht_index)
          opt.spatialstreams = MCS_TABLE[ht_index][0]
        else:
          opt[name] = v if len(v) > 1 else v[0]
        ofs += sz

    (fctl, duration) = struct.unpack('<HH', frame[0:4])
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
        if len(frame) < ofs + 2: break
        seq = struct.unpack('<H', frame[ofs:ofs + 2])[0]
        opt.seq = (seq & 0xfff0) >> 4
        opt.frag = (seq & 0x000f)
        ofs += 2
      else:  # ta, ra, xa
        if len(frame) < ofs + 6: break
        opt[fieldname] = MacAddr(frame[ofs:ofs + 6])
        ofs += 6

    # ACK and CTS packets omit TA field for efficiency, so we have to fill
    # it in from the previous packet's RA field.  We can check that the
    # new packet's RA == the previous packet's TA, just to make sure we're
    # not lying about it.
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

    yield opt, frame


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
    for opt, frame in Packetize(p):
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
      if 'mcs' in opt:
        print(
            src, opt.dsmode, opt.typestr, ts, opt.rate, mac_usecs,
            opt.orig_len, seq, opt.flags)
      else:
        print(
            src, opt.dsmode, opt.typestr, ts, opt.rate, mac_usecs,
            opt.orig_len, seq, opt.flags)


def ZOpen(fn):
  if fn.endswith('.bz2'):
    return bz2.BZ2File(fn)
  return open(fn)


if __name__ == '__main__':
  Example(ZOpen(sys.argv[1]))
