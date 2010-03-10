#!/usr/bin/env python

import sys
import os
import os.path
import re
import struct
import optparse

BR_DICT = {
    'bps': [0x0b, 2, '<H'],             # bytes per sector
    'spc': [0x0d, 1, 'B'],              # sectors per cluster
    'rsvd_sects': [0x0e, 2, '<H'],      # reserved sectors from boot record
    'n_fats': [0x10, 1, 'B'],           # number of FATs
    'rdents': [0x11, 2, '<H'],          # number of rootdir entries
    'spf': [0x16, 2, '<H'],             # sectors per FAT
    'spt': [0x18, 2, '<H'],             # sectors per track
    'heads': [0x1a, 2, '<H'],           # heads (sides)
    'magic': [0x1fe, 2, '<H']           # boot record magic
}

DENTRY_DICT = {
    'nam': [0x00, 8, '8s'],             # short name (8 chars)
    'ext': [0x08, 3, '3s'],             # short extension (3 chars)
    'size': [0x1c, 4, '<I'],            # size in bytes
    'cluster': [0x1a, 2, '<H'],         # first cluster
    'flags': [0x0b, 1, 'B'],            # R/O, hidden, system etc.
    'lfncksum': [0x0d, 1, 'B'],         # LFN checksum
    'nt': [0x0c, 1, 'B'],               # unknown
    'lfnf': [0x00, 1, 'B'],             # LFN flags: isLast and index
    'lfn1': [0x01, 10, '10s'],          # LFN part1
    'lfn2': [0x0e, 12, '12s'],          # LFN part2
    'lfn3': [0x1c, 4, '4s']             # LFN part3
}

ATTR_MASK_LIST = [('v', 0x08), ('d', 0x10), ('r', 0x01),
                  ('h', 0x02), ('s', 0x04), ('a', 0x20)]
ATTR2MASK_MAP = dict(ATTR_MASK_LIST)

def parse(fmt_dict, buf):
    d = {}
    for k, v in fmt_dict.iteritems():
        d[k] = struct.unpack(v[2], buf[v[0]:v[0]+v[1]])[0]
    return d

# Blocks Chain (chain of sectors, clusters & so on)
class BChain(object):
    def __init__(self, f, blist, bsize=512, boffs=0):
        self.f = f              # device/file
        self.blist = blist      # list of block numbers
        self.bsize = bsize      # blosk size
        self.boffs = boffs      # block area offset

    def __len__(self):
        return len(self.blist) * self.bsize

    def offs(self, pos):
        n, p = divmod(pos, self.bsize)
        return self.boffs + self.blist[n]*self.bsize + p

    def _read(self, pos, size):
        # Reads data up to the end of sector.
        # Return less than the requested size when the requested region
        # spans several sectors
        buf = ''
        n, p = divmod(pos, self.bsize)
        o = self.boffs + self.blist[n]*self.bsize + p
        self.f.seek(o, os.SEEK_SET)

        # limit the requested size:
        if p + size > self.bsize:
            size = self.bsize - p

        # read until success or EOF:
        while len(buf) < size:
            b = self.f.read(size - len(buf))
            if b == '':
                raise IOError("EOF at sector #%i, byte #%i" % (
                        self.blist[n], p + len(buf)))
            buf += b
        return buf

    def read(self, pos, size):
        buf = ''
        while len(buf) < size:
            b = self._read(pos + len(buf), size - len(buf))
            if b == '':
                raise IOError("EOF at pos %i" % (pos + len(buf)))
            buf += b
        return buf

    @classmethod
    def get(f, pos, size, blist=[0], bsize=512, boffs=0):
        return BChain(f=f, blist=blist, bsize=512, boffs=0).read(pos, size)

def get_dirents(d_chain):
    de_cnt = len(d_chain) / 32
    de_list, cur_lfn_parts = [], {}
    cur_lfn_cksum = cur_lfn_maxnum = cur_lfn_offs = None

    for i in range(de_cnt):
        de_buf = d_chain.read(i*32, 32)
        if de_buf == '\0' * 32:
            break

        de = parse(DENTRY_DICT, de_buf)
        de['raw'] = de_buf
        de['ofs'] = d_chain.offs(i * 32)        # offset of SFN
        de['offs'] = de['ofs']                  # offset of LFN
        assert(not (de['flags'] & ATTR2MASK_MAP['v']
                    and de['flags'] & ATTR2MASK_MAP['d']))
        if de['flags'] & ATTR2MASK_MAP['v']:
            de['attrs'] = 'v'
        elif de['flags'] & ATTR2MASK_MAP['d']:
            de['attrs'] = 'd'
        else:
            de['attrs'] = '-'

        for a, m in ATTR_MASK_LIST[2:]:
            if de['flags'] & m:
                de['attrs'] += a
            else:
                de['attrs'] += '-'

        if de['flags'] == 0x0f:
            assert(de['cluster'] == 0x0000)

            if de['nam'][:1] == '\xe5':
                de['type'] = 'deln'
            else:
                de['type'] = 'lfn'
                de['lfni'] = de['lfnf'] & ~0x40
                if de['lfnf'] & 0x40:
                    cur_lfn_maxnum = de['lfni']
                assert(de['lfni'] > 0 and de['lfni'] <= 20
                       and (cur_lfn_maxnum is None
                            or de['lfni'] <= cur_lfn_maxnum))
                assert(cur_lfn_cksum is None
                       or cur_lfn_cksum == de['lfncksum'])
                cur_lfn_parts[de['lfni']] = \
                    de['lfn1'] + de['lfn2'] + de['lfn3']

                # FIXME: Calculate LFN offset as offset of the first
                # encountered LFN entry (not the one with isLast flag):
                if cur_lfn_offs is None:
                    cur_lfn_offs = de['ofs']
        else:
            if de['flags'] == 0x08:
                de['type'] = 'vol'
                de['name'] = de['nam'].rstrip() + de['ext'].rstrip()
            elif de['nam'][:1] == '\xe5':
                if de['flags'] & ATTR2MASK_MAP['d']:
                    de['type'] = 'deld'
                else:
                    de['type'] = 'delf'
            else:
                if cur_lfn_parts:
                    assert(cur_lfn_maxnum == len(cur_lfn_parts.keys()))
                    de['namu'] = ''.join([cur_lfn_parts[k] for k in \
                                              sorted(cur_lfn_parts.keys())])
                    assert(not (len(de['namu']) % 1))

                    de['name'] = ''
                    # Convert from little-endian byte representation of
                    # UCS16 string to Python's native unicode:
                    for i in range(len(de['namu']) / 2):
                        (l, h) = struct.unpack('BB', de['namu'][i*2:i*2+2])
                        if not (l or h):
                            break
                        de['name'] += unichr((h << 8) + l)

                    # Store LFN offset
                    de['offs'] = cur_lfn_offs
                else:
                    # LFN not provided, so use entry's short name instead:
                    de['name'] = de['nam'].rstrip()
                    if de['ext'].rstrip() != '':
                        de['name'] += '.' + de['ext'].rstrip()
                de['type'] = (de['flags'] & ATTR2MASK_MAP['d']) \
                    and 'dir' or 'file'

            cur_lfn_parts = {}
            cur_lfn_cksum = cur_lfn_maxnum = cur_lfn_offs = None
            de_list.append(de)

    return de_list

def get_clist(br, de):
    """Get cluster list for the given directory entry
    """
    if de['type'] == 'vol':
        assert(de['size'] == 0 and de['cluster'] == 0)
        return []

    assert(de['type'] in ('dir', 'file'))
    assert(de['cluster'] >= 2 and de['cluster'] <= 0xfff8
           or de['size'] == 0 and de['cluster'] == 0)
    fat1bchain = BChain(br['dev'], [0], bsize=br['spf']*br['bps'],
                        boffs=br['fat1offs'])

    s = fat1bchain.read(0, 4)
    if s != '\xf8\xff\xff\xff':
        print >>sys.stderr, '*WARNING* suspicious start of FAT at 0x%x:' % \
            br['fat1offs'],
        print >>sys.stderr, '%02x%02x %02x%02x' % \
            tuple([ord(s[i]) for i in range(4)])

    c = de['cluster']
    clist = []
    while c >= 2 and c < 0xfff7:
        clist.append(c)
        c = struct.unpack('<H', fat1bchain.read(c*2, 2))[0]
    return clist

def ls_dirents(br, de_list, base_path=None):
    global opts
    for de in de_list:
        # Dir/file/volume label
        sz = ''
        if opts.size == 'bytes':
            sz = ' %10i' % de['size']
        elif opts.size == 'clusters':
            sz = ' %5i' % len(get_clist(br, de))
        elif opts.size == 'sectors':
            sz = ' %8i' % (len(get_clist(br, de)) * br['spc'])

        if base_path is None:
            name = de['name']
        else:
            name = os.path.join(base_path, de['name'])

        print '%5s +%08x%s %s' % (
            de['attrs'], de['offs'], sz, name.encode('utf8'))

def _ls_path(br, dir_cache, head, tail):
    global opts
    de_list = filter(
        lambda x: (x['type'] not in ('deld', 'delf', 'deln', 'lfn')) \
            and (x['name'] not in ('.', '..')),
        get_dirents(dir_cache[head]))

    # sort dentries alphabetically
    de_list.sort(key=lambda x: x['name'])

    if tail:
        p = tail.pop(0)
        orig_head, head = head, os.path.join(head, p)

        for de in de_list:
            if de['type'] == 'file' and de['name'] == p:
                return ls_dirents(br, [de], opts.recurse and orig_head or None)
            elif de['type'] == 'dir' and de['name'] == p:
                de_clist = get_clist(br, de)
                if head not in dir_cache:
                    dir_cache[head] = BChain(br['dev'], blist=de_clist,
                                             bsize=br['spc']*br['bps'],
                                             boffs=br['c0offs'])
                return _ls_path(br, dir_cache, head, tail)
        print '**ERROR** "%s" does not exist' % head
    else:
        if not opts.recurse:
            return ls_dirents(br, de_list)

        for de in de_list:
            ls_dirents(br, [de], head)
            if de['type'] == 'dir':
                de_clist = get_clist(br, de)
                path_de_str = os.path.join(head, de['name'])
                if path_de_str not in dir_cache:
                    dir_cache[path_de_str] = BChain(br['dev'], blist=de_clist,
                                                    bsize=br['spc']*br['bps'],
                                                    boffs=br['c0offs'])
                _ls_path(br, dir_cache, path_de_str, [])

def ls_path(br, dir_cache, path):
    ps = os.path.normcase(os.path.normpath(path)).split(os.path.sep)
    if ps[0] == '':
        ps.pop(0)
    if ps[-1] in ('', '.'):
        ps.pop()
    return _ls_path(br, dir_cache, os.path.sep, ps)

def mkbr(f):
    """Parse boot sector.

    AFAIU, `br' is an acronym for ``boot record''.  --vvv
    """
    br = parse(BR_DICT, f.read(512))
    br['dev'] = f
    assert(br['magic'] == 0xaa55)
    assert(br['bps'] in (256, 512, 2048))

    # byte offsets of FAT1, FAT2 & so on
    # (in fact, never saw more than two FATs on disk)
    for i in range(1, br['n_fats'] + 1):
        br['fat%ioffs' % i] = br['rsvd_sects'] * br['bps'] + \
            i * br['spf'] * br['bps']

    # bytes per root directory
    br['bprd'] = br['rdents'] * 32

    # sectors per root directory
    br['sprd'] = (br['bprd'] + br['bps'] - 1) / br['bps']

    # byte offset of root directory
    br['rd_offs'] = (br['rsvd_sects'] + br['n_fats'] * br['spf']) * br['bps']

    # byte offsets of cluster #2 and cluster #0
    br['c2offs'] = br['rd_offs'] + br['sprd'] * br['bps']
    br['c0offs'] = br['c2offs'] - 2 * br['spc'] * br['bps']

    return br

# ----------------------------------------------------------------------
if __name__ == '__main__':
    global opts
    op = optparse.OptionParser('USAGE: %prog [OPTION]... DEV [PATH]...')
    op.add_option('-b', '--byte', dest='size', action='store_const',
                  const='bytes', help='print size in bytes')
    op.add_option('-c', '--clusters', dest='size', action='store_const',
                  const='clusters', help='print size in clusters')
    op.add_option('-s', '--sectors', dest='size', action='store_const',
                  const='sectors', help='print size in sectors')
    op.add_option('-r', '--recurse', dest='recurse', action='store_true',
                  help='recurse into directories like find does')
    (opts, args) = op.parse_args()

    try: dev = args.pop(0) # exclude dev from args
    except IndexError:
        print >>sys.stderr, """Insufficient number of non-optional arguments.
Type `%s -h' for usage.""" % sys.argv[0]
        sys.exit(1)

    if not args:
        args.append(os.path.sep)

    br = mkbr(file(dev))

    # pre-cache the root directory
    dir_cache = {os.path.sep: BChain(br['dev'], [0], bsize=br['bprd'],
                                     boffs=br['rd_offs'])}
    for path in args:
        ls_path(br, dir_cache, path)

# vi:set sw=4 et:
