#!/home/tiancj/python/py3k/bin/python

import sys
import getopt
import socket
# import struct
# import fcntl
import eloop
import dpkt

ETH_P_ALL = 0x0003
SIOCGIFINDEX = 0x8933


class Sniffer(object):
    def __init__(self):
        self.workers = []
        self.eloop = eloop.EventLoop()

    def add_worker(self, worker):
        self.workers.append(worker)

    def start(self):
        for w in self.workers:
            w.init()
        self.eloop.run()


class SnifferWorker(object):
    def __init__(self, sniffer, ifname = None):
        self.ifname = ifname
        self.sock = None
        sniffer.add_worker(self)
        self.eloop = sniffer.eloop

    def __str__(self):
        return 'SnifferWorker: <ifname %s>' % self.ifname

    def create_raw_socket(self):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.setblocking(False)
        # get the index of the interface
        # ret = fcntl.ioctl(self.sock, SIOCGIFINDEX, struct.pack('=6sI', bytes(self.ifname, 'ascii'), 0))
        # tmp, ifindex = struct.unpack('=6sI', ret)
        # print("ifname %s: ifindex %d" % (self.ifname, ifindex))
        self.sock.bind((self.ifname, ETH_P_ALL))

    def on_raw_packet_received(self, fd, mask):
        print('packet on <%s> received' % self.ifname)
        # receive complete one pkt
        buf = fd.recv(4096, socket.MSG_TRUNC)
        if buf:
            print(dpkt.hexdump(buf))
            radiotap_hdr = dpkt.radiotap.Radiotap(buf)
            if radiotap_hdr.channel_present and radiotap_hdr.channel.freq:
                print("Channel: %d" % radiotap_hdr.channel.freq)
            if radiotap_hdr.rate_present and radiotap_hdr.rate.val:
                print("Rate: %d" % radiotap_hdr.rate.val)

            ieee80211_pkt = radiotap_hdr.data
            if ieee80211_pkt:
                print(ieee80211_pkt.subtype)

    def init(self):
        self.create_raw_socket()
        self.eloop.register(self.sock, eloop.EVENT_READ, self.on_raw_packet_received)


def usage(program):
    print("Usage: %s [-i <ifname>]", program)


def main():
    sniffer = Sniffer()
    worker = SnifferWorker(sniffer)
    opts, args = getopt.getopt(sys.argv[1:], "dDhi:Nt")
    for o, a in opts:
        if o == '-h':
            usage(sys.argv[0])
            return
        elif o == '-i':
            worker.ifname = a
        elif o == '-N':
            worker = SnifferWorker(sniffer)

    for w in sniffer.workers:
        print(w)
    sniffer.start()


if __name__ == '__main__':
    main()