# $Id: dpkt.py 43 2007-08-02 22:42:59Z jon.oberheide $
# -*- coding: utf-8 -*-
"""Simple packet creation and parsing."""

import copy
import itertools
import socket
import struct
import array
import sys


class Error(Exception):
    pass


class UnpackError(Error):
    pass


class NeedData(UnpackError):
    pass


class PackError(Error):
    pass


class _MetaPacket(type):
    def __new__(cls, clsname, clsbases, clsdict):
        t = type.__new__(cls, clsname, clsbases, clsdict)
        st = getattr(t, '__hdr__', None)
        if st is not None:
            # XXX - __slots__ only created in __new__()
            clsdict['__slots__'] = [x[0] for x in st] + ['data']
            t = type.__new__(cls, clsname, clsbases, clsdict)
            t.__hdr_fields__ = [x[0] for x in st]
            t.__hdr_fmt__ = getattr(t, '__byte_order__', '>') + ''.join([x[1] for x in st])
            t.__hdr_len__ = struct.calcsize(t.__hdr_fmt__)
            t.__hdr_defaults__ = dict(list(zip(
                t.__hdr_fields__, [x[2] for x in st])))
        return t


class Packet(metaclass=_MetaPacket):
    """Base packet class, with metaclass magic to generate members from
    self.__hdr__.

    __hdr__ should be defined as a list of (name, structfmt, default) tuples
    __byte_order__ can be set to override the default ('>')

    Example::

    >>> class Foo(Packet):
    ...   __hdr__ = (('foo', 'I', 1), ('bar', 'H', 2), ('baz', '4s', 'quux'))
    ...
    >>> foo = Foo(bar=3)
    >>> foo
    Foo(bar=3)
    >>> str(foo)
    '\x00\x00\x00\x01\x00\x03quux'
    >>> foo.bar
    3
    >>> foo.baz
    'quux'
    >>> foo.foo = 7
    >>> foo.baz = 'whee'
    >>> foo
    Foo(baz='whee', foo=7, bar=3)
    >>> Foo('hello, world!')
    Foo(baz=' wor', foo=1751477356L, bar=28460, data='ld!')
    """

    def __init__(self, *args, **kwargs):
        """Packet constructor with ([buf], [field=val,...]) prototype.

        Arguments:

        buf -- optional packet buffer to unpack

        Optional keyword arguments correspond to members to set
        (matching fields in self.__hdr__, or 'data').
        """
        self.data = b''
        if args:
            try:
                self.unpack(args[0])
            except struct.error:
                if len(args[0]) < self.__hdr_len__:
                    raise NeedData
                raise UnpackError('invalid %s: %r' %
                                  (self.__class__.__name__, args[0]))
        else:
            for k in self.__hdr_fields__:
                setattr(self, k, copy.copy(self.__hdr_defaults__[k]))
            try:
                ki = kwargs.iteritems()
            except:
                ki = kwargs.items()
            for k, v in ki:
                setattr(self, k, v)

    def __len__(self):
        return self.__hdr_len__ + len(self.data)

    def __getitem__(self, k):
        try:
            return getattr(self, k)
        except AttributeError:
            raise KeyError

    def __repr__(self):
        # Collect and display protocol fields in order:
        # 1. public fields defined in __hdr__, unless their value is default
        # 2. properties derived from _private fields defined in __hdr__
        # 3. dynamically added fields from self.__dict__, unless they are _private
        # 4. self.data when it's present

        l = []
        # maintain order of fields as defined in __hdr__
        for field_name, _, _ in getattr(self, '__hdr__', []):
            field_value = getattr(self, field_name)
            if field_value != self.__hdr_defaults__[field_name]:
                if field_name[0] != '_':
                    l.append('%s=%r' % (field_name, field_value))  # (1)
                else:
                    # interpret _private fields as name of properties joined by underscores
                    for prop_name in field_name.split('_'):        # (2)
                        if isinstance(getattr(self.__class__, prop_name, None), property):
                            l.append('%s=%r' % (prop_name, getattr(self, prop_name)))
        # (3)
        try:
            di = self.__dict__.iteritems()
        except:
            di = self.__dict__.items()
        l.extend(
            ['%s=%r' % (attr_name, attr_value)
             for attr_name, attr_value in di
             if attr_name[0] != '_'                   # exclude _private attributes
             and attr_name != self.data.__class__.__name__.lower()])  # exclude fields like ip.udp
        # (4)
        if self.data:
            l.append('data=%r' % self.data)
        return '%s(%s)' % (self.__class__.__name__, ', '.join(l))

    def __str__(self):
        return str(self.__bytes__())
    
    def __bytes__(self):
        return self.pack_hdr() + bytes(self.data)

    def pack_hdr(self):
        """Return packed header string."""
        try:
            return struct.pack(self.__hdr_fmt__,
                               *[getattr(self, k) for k in self.__hdr_fields__])
        except struct.error:
            vals = []
            for k in self.__hdr_fields__:
                v = getattr(self, k)
                if isinstance(v, tuple):
                    vals.extend(v)
                else:
                    vals.append(v)
            try:
                return struct.pack(self.__hdr_fmt__, *vals)
            except struct.error as e:
                raise PackError(str(e))

    def pack(self):
        """Return packed header + self.data string."""
        return bytes(self)

    def unpack(self, buf):
        """Unpack packet header fields from buf, and set self.data."""
        for k, v in zip(self.__hdr_fields__,
                                   struct.unpack(self.__hdr_fmt__, buf[:self.__hdr_len__])):
            setattr(self, k, v)
        self.data = buf[self.__hdr_len__:]

# XXX - ''.join([(len(`chr(x)`)==3) and chr(x) or '.' for x in range(256)])
__vis_filter = b"""................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................................."""


def hexdump(buf, length=16):
    """Return a hexdump output string of the given buffer."""
    n = 0
    res = []
    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = ' '.join(['%02x' % x for x in line])
        line = line.translate(__vis_filter)
        res.append('  %04d:  %-*s %s' % (n, length * 3, hexa, line))
        n += length
    return '\n'.join(res)


def in_cksum_add(s, buf):
    n = len(buf)
    cnt = (n // 2) * 2
    a = array.array('H', buf[:cnt])
    if cnt != n:
        a.append(struct.unpack('H', buf[-1] + '\x00')[0])
    return s + sum(a)


def in_cksum_done(s):
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return socket.ntohs(~s & 0xffff)


def in_cksum(buf):
    """Return computed Internet checksum."""
    return in_cksum_done(in_cksum_add(0, buf))

def cpu_to_le32(v):
    return struct.unpack('<I', struct.pack('=I', v))[0]

def cpu_to_be32(v):
    return struct.unpack('>I', struct.pack('=I', v))[0]

def le32_to_cpu(v):
    if sys.byteorder == 'little':
        return v
    else:
        return struct.unpack('>I', struct.pack('=I', v))

def be32_to_cpu(v):
    if sys.byteorder != 'little':
        return v
    else:
        return struct.unpack('>I', struct.pack('=I', v))

if __name__ == '__main__':
    print("%x" % cpu_to_le32(0x12345678))
    print("%x" % cpu_to_be32(0x12345678))
    print("%x" % le32_to_cpu(0x12345678))
    print("%x" % be32_to_cpu(0x12345678))