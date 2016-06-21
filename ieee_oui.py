import re


class OuiTable(object):
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
