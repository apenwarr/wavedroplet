#!/usr/bin/env python2

from __future__ import print_function
import gzip
import bz2
import csv
import os
import string
import struct
import subprocess
import sys

class Struct(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.__dict__.update(**kwargs)
    def __getattr__(self, name):
        return self[name]
    def __setattr__(self, name, value):
        self[name] = value
    def __delattr__(self, name):
        del self[name]

TCPDUMP_MAGIC = 0xa1b2c3d4
TCPDUMP_VERSION = (2, 4)
LINKTYPE_IEEE802_11_RADIOTAP = 127

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
    (1, "BPSK", "1/2", (6.50, 7.20, 13.50, 15.00)),
    (1, "QPSK", "1/2", (13.00, 14.40, 27.00, 30.00)),
    (1, "QPSK", "3/4", (19.50, 21.70, 40.50, 45.00)),
    (1, "16-QAM", "1/2", (26.00, 28.90, 54.00, 60.00)),
    (1, "16-QAM", "3/4", (39.00, 43.30, 81.00, 90.00)),
    (1, "64-QAM", "2/3", (52.00, 57.80, 108.00, 120.00)),
    (1, "64-QAM", "3/4", (58.50, 65.00, 121.50, 135.00)),
    (1, "64-QAM", "5/6", (65.00, 72.20, 135.00, 150.00)),
    (2, "BPSK", "1/2", (13.00, 14.40, 27.00, 30.00)),
    (2, "QPSK", "1/2", (26.00, 28.90, 54.00, 60.00)),
    (2, "QPSK", "3/4", (39.00, 43.30, 81.00, 90.00)),
    (2, "16-QAM", "1/2", (52.00, 57.80, 108.00, 120.00)),
    (2, "16-QAM", "3/4", (78.00, 86.70, 162.00, 180.00)),
    (2, "64-QAM", "2/3", (104.00, 115.60, 216.00, 240.00)),
    (2, "64-QAM", "3/4", (117.00, 130.00, 243.00, 270.00)),
    (2, "64-QAM", "5/6", (130.00, 144.40, 270.00, 300.00)),
    (3, "BPSK", "1/2", (19.50, 21.70, 40.50, 45.00)),
    (3, "QPSK", "1/2", (39.00, 43.30, 81.00, 90.00)),
    (3, "QPSK", "3/4", (58.50, 65.00, 121.50, 135.00)),
    (3, "16-QAM", "1/2", (78.00, 86.70, 162.00, 180.00)),
    (3, "16-QAM", "3/4", (117.00, 130.00, 243.00, 270.00)),
    (3, "64-QAM", "2/3", (156.00, 173.30, 324.00, 360.00)),
    (3, "64-QAM", "3/4", (175.50, 195.00, 364.50, 405.00)),
    (3, "64-QAM", "5/6", (195.00, 216.70, 405.00, 450.00)),
    (4, "BPSK", "1/2", (26.00, 28.80, 54.00, 60.00)),
    (4, "QPSK", "1/2", (52.00, 57.60, 108.00, 120.00)),
    (4, "QPSK", "3/4", (78.00, 86.80, 162.00, 180.00)),
    (4, "16-QAM", "1/2", (104.00, 115.60, 216.00, 240.00)),
    (4, "16-QAM", "3/4", (156.00, 173.20, 324.00, 360.00)),
    (4, "64-QAM", "2/3", (208.00, 231.20, 432.00, 480.00)),
    (4, "64-QAM", "3/4", (234.00, 260.00, 486.00, 540.00)),
    (4, "64-QAM", "5/6", (260.00, 288.80, 540.00, 600.00)),
    (1, "BPSK", "1/2", (0, 0, 6.50, 7.20)),
]

def mcs2rate(tb):
#    known=tb[0]
#    flags=tb[1]
# ********************************************
# ************* currently broken code here ***
# ************ FIXME FIXME FIXME FIXME *******
# ********************************************
    if known & (1 << 0):
        bw=(20,40,20,20)[flags & 0x3]
    else:
        bw=20
    if known & (1 << 2):
        gi=((flags&0x4) >> 2)
    else:
        gi=0
    if known & (1 << 1):
        mcs=tb[2]
    else:
        mcs=0
    if bw==20:
        si=0
    else:
        si=2
    if gi:
        si += 1
    return MCS_TABLE[mcs][3][si]


def Packetize(stream):
  # pcap global header
  magicbytes = stream.read(4)
  if struct.unpack('<I', magicbytes) == (TCPDUMP_MAGIC,):
    byteorder = '<'
  elif struct.unpack('>I', magicbytes) == (TCPDUMP_MAGIC,):
    byteorder = '>'
  else:
    raise ValueError('unexpected tcpdump magic %r' % magicbytes)
  (version_major, version_minor,
   unused_thiszone,
   unused_sigfigs,
   snaplen,
   network) = struct.unpack(byteorder + 'HHiIII', stream.read(20))
  version = (version_major, version_minor)
  if version != TCPDUMP_VERSION:
    raise ValueError('unexpected tcpdump version %r' % version)
  if network != LINKTYPE_IEEE802_11_RADIOTAP:
    raise ValueError('unexpected tcpdump network type %r' % network)

  while 1:
    opt = Struct({})

    # pcap packet header
    bytes = stream.read(16)
    if len(bytes) < 16: break  # EOF
    (ts_sec, ts_usec,
     incl_len, orig_len) = struct.unpack(byteorder + 'IIII', bytes)
    if incl_len > orig_len:
      raise ValueError('packet incl_len(%d) > orig_len(%d): invalid'
                       % (incl_len, orig_len))
    if incl_len > snaplen:
      raise ValueError('packet incl_len(%d) > snaplen(%d): invalid'
                       % (incl_len, snaplen))

    opt.pcap_secs = ts_sec + (ts_usec / 1e6)

    # pcap packet data
    radiotap = stream.read(incl_len)

    opt.incl_len = incl_len
    opt.orig_len = orig_len


    # radiotap header (always little-endian)
    (it_version, unused_it_pad,
     it_len, it_present) = struct.unpack('<BBHI', radiotap[:8])
    if it_version != 0:
      raise ValueError('unknown radiotap version %d' % it_version)
    frame = radiotap[it_len:]
    optbytes = radiotap[8:it_len]

    ofs = 0
    for i, (name, format) in enumerate(RADIOTAP_FIELDS):
      if it_present & (1 << i):
        ofs = Align(ofs, struct.calcsize(format[0]))
        sz = struct.calcsize(format)
        v = struct.unpack(format, optbytes[ofs:ofs+sz])
        if name == 'mac_usecs':
          opt.mac_usecs = v[0]
          # opt.mac_secs = v[0] / 1e6
        elif name == 'channel':
          opt.freq = v[0]
          opt.channel_flags = v[1]
        elif name == 'ht':
          opt.ht = v
          opt.mcs = v[2]
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
        seq = struct.unpack('<H', frame[ofs:ofs+2])[0]
        opt.seq = (seq & 0xfff0) >> 4
        opt.frag = (seq & 0x000f)
        ofs += 2
      else:
        opt[fieldname] = MacAddr(frame[ofs:ofs+6])
        ofs += 6
    
    yield opt, frame


def d(p):
  basetime=0
  if 0:
    for opt, frame in Packetize(p):
        ts=opt.pcap_secs
        if basetime:
            ts -= basetime
        else:
            basetime=ts
            ts=0
        print (ts, opt)
#      print HexDump(frame)
  elif 1:
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
#      sys.stdout.flush()
  else:
      try:
          for opt, frame in Packetize(p):
              ts=opt.pcap_secs
#              if basetime:
#                  ts -= basetime
#              else:
#                  basetime=ts
#                  ts=0
              ts="%.09f"%ts
              if 'xa' in opt:
                  src=opt.xa
              else:
                  src='no:xa:00:00:00:00'
              if 'mac_usecs' in opt:
#                  if opt.mac_usecs > 4294967296:
#                      continue
                  mac_usecs = opt.mac_usecs
              else:
                  mac_usecs = 0
              if 'seq' in opt:
                  seq = opt.seq
              else:
                  seq = 'noseq'
              if 'flags' in opt:
                  if opt.flags & 0x40:    # "Bad FCS" flag in radiotap header
                      continue
              if 'mcs' in opt:
                  print (src, opt.dsmode, opt.typestr, ts, mcs2rate(opt.mcs), mac_usecs, opt.orig_len, seq, opt.flags)
              else:
                  print (src, opt.dsmode, opt.typestr, ts, opt.rate, mac_usecs, opt.orig_len, seq, opt.flags)

      finally:
          pass

def zopen(fn):
    if fn.endswith(".bz2"):
        return bz2.BZ2File(fn)
    if fn.endswith(".gz"):
        return gzip.open(fn)
    return open(fn)

if __name__ == '__main__':
    p=zopen(sys.argv[1])
    d(p)
