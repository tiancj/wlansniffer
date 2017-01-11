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


class StationCache(object):
    def __init__(self):
        self.mac = None
        self.time = None

    def __hash__(self):
        pass


class Sniffer(object):
    def __init__(self):
        self.workers = []
        self.sta_database = {}
        self.ap_database = {}
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
        if mask != eloop.EVENT_READ:
            return

        # receive complete one pkt
        buf = fd.recv(4096, socket.MSG_TRUNC)
        if buf:
            # print(dpkt.hexdump(buf))
            radiotap_hdr = dpkt.radiotap.Radiotap(buf)
            if radiotap_hdr.rate_present and radiotap_hdr.rate.val and radiotap_hdr.ant_sig_present:
                ieee80211_pkt = radiotap_hdr.data
                if not ieee80211_pkt:
                    return
                channel = radiotap_hdr.channel.freq
                signal = radiotap_hdr.ant_sig.db
                type = ieee80211_pkt.type
                if type == dpkt.ieee80211.MGMT_TYPE:
                    self._handle_mgmt(ieee80211_pkt, channel=channel, signal=signal)
                elif type == dpkt.ieee80211.DATA_TYPE:
                    self._handle_data(ieee80211_pkt, channel=channel, signal=signal)

    def _ieee80211_get_bssid(self, hdr):
        if len(hdr) < 16:
            return None
        if hdr.type == dpkt.ieee80211.DATA_TYPE:
            if len(hdr) < 24:
                return None
        elif hdr.type == dpkt.ieee80211.MGMT_TYPE:
            return None
        return None

    def _ieee80211_rx_mgmt_beacon(self, data):
        pass

    def _handle_mgmt(self, data, **kwarg):
        stype = data.subtype
        if stype == dpkt.ieee80211.M_BEACON:
            self._ieee80211_rx_mgmt_beacon(data)
            return

        parsed = True
        bssid = data.mgmt.bssid
        sta_addr = None
        if stype == dpkt.ieee80211.M_ASSOC_REQ:
            sta_addr = data.mgmt.src
        elif stype == dpkt.ieee80211.M_ASSOC_RESP:
            sta_addr = data.mgmt.dst
        elif stype == dpkt.ieee80211.M_PROBE_REQ:
            sta_addr = data.mgmt.src
        elif stype == dpkt.ieee80211.M_PROBE_RESP:
            parsed = False
            sta_addr = data.mgmt.dst
        elif stype == dpkt.ieee80211.M_REASSOC_REQ:
            sta_addr = data.mgmt.src
        elif stype == dpkt.ieee80211.M_REASSOC_RESP:
            sta_addr = data.mgmt.dst
        elif stype == dpkt.ieee80211.M_AUTH or stype == dpkt.ieee80211.M_DEAUTH or stype == dpkt.ieee80211.M_ACTION:
            parsed = False
            sta_addr = data.mgmt.dst
            if sta_addr == data.mgmt.src:
                sta_addr = data.mgmt.src
        if not self.is_broadcast_ether_addr(bssid):
            print("MGMT: bssid: %s, sta_addr: %s" % (self._to_mac_string(bssid), self._to_mac_string(sta_addr)))


    @staticmethod
    def _to_mac_string(mac):
        return ':'.join('{:02x}'.format(c) for c in mac)

    @staticmethod
    def is_zero_ether_addr(mac):
        return mac == b'\x00'*6

    @staticmethod
    def is_multicast_ether_addr(mac):
        return mac[0] & 0x1

    @staticmethod
    def is_local_ether_addr(mac):
        return mac[0] & 0x2

    @staticmethod
    def is_broadcast_ether_addr(mac):
        return mac == b'\xff' * 6

    def _handle_data(self, data, **kwargs):
        # print("_handle_data")
        if data.data_frame:
            bssid = data.data_frame.bssid
            sta_addr = None
            if data.to_ds and data.from_ds: # WDS or mesh
                return
            if data.to_ds:
                sta_addr = data.data_frame.src
            elif data.from_ds:
                sta_addr = data.data_frame.dst
            if sta_addr is None:
                return
            print("DATA: bssid: %s, sta_addr: %s" % (self._to_mac_string(bssid), self._to_mac_string(sta_addr)))


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