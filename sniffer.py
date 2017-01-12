#!/home/tiancj/python/py3k/bin/python

import sys
import getopt
import socket
# import struct
# import fcntl
import eloop
import dpkt
import struct
import time
import os

ETH_P_ALL = 0x0003
SIOCGIFINDEX = 0x8933


class StationDatabase(object):

    STATION_HASH_ID_NUM = 10240

    def __init__(self):
        self.sta_macs = {}

    def hash(self, mac):
        val1, val2, val3 = struct.unpack('HHH', mac)
        return (val1 ^ val2 ^ val3) & (self.STATION_HASH_ID_NUM - 1)

    def insert_sta_to_database(self, sta):
        hash = self.hash(sta.mac)
        if hash not in self.sta_macs:
            self.sta_macs[hash] = []
            self.sta_macs[hash].append(sta)
        else:
            found = False
            for e in self.sta_macs[hash]:
                if e == sta: # update members
                    found = True
                    e.time = sta.time
            if not found:
                self.sta_macs[hash].append(sta)

    def __str__(self):
        ret = ''
        for hash, stations in self.sta_macs.items():
            ret.join('hash: %x, stations: %s' % (hash, stations))
        return ret


class APDatabase(object):

    AP_HASH_ID_NUM = 10240

    def __init__(self):
        self.ap_macs = {}

    def hash(self, mac):
        val1, val2, val3 = struct.unpack('HHH', mac)
        return (val1 ^ val2 ^ val3) & (self.AP_HASH_ID_NUM - 1)

    def insert_sta_to_database(self, ap):
        hash = self.hash(ap.mac)
        if hash not in self.ap_macs:
            self.ap_macs[hash] = []
            self.ap_macs[hash].append(ap)
        else:
            found = False
            for e in self.ap_macs[hash]:
                if e == ap: # update members
                    found = True
                    e.time = ap.time
            if not found:
                self.ap_macs[hash].append(ap)

    def __str__(self):
        ret = ''
        print("self.ap_macs", self.ap_macs)
        for h, stations in self.ap_macs.items():
            ret.join('hash: %x, stations: %s' % (h, stations))
        return ret

    __repr__ = __str__


class StationCache(object):

    def __init__(self, mac, time, **kwargs):
        self.mac = mac
        self.time = time
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __eq__(self, other):
        if self.mac == other.mac:
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        if getattr(self, 'ssid'):
            return '<ap %s %s>' % (SnifferWorker._to_mac_string(self.mac), self.ssid)
        return '<sta %s>' % SnifferWorker._to_mac_string(self.mac)

    __repr__ = __str__


class Sniffer(object):
    def __init__(self, ctrl_path='/tmp/sniffer.sock'):
        self.workers = []
        self.sta_database = StationDatabase()
        self.ap_database = APDatabase()
        self.eloop = eloop.EventLoop()
        self.ctrl_path = ctrl_path
        self.ctrl_sock = None

    def insert_sta_to_database(self, sta):
        self.sta_database.insert_sta_to_database(sta)

    def insert_ap_to_database(self, ap):
        self.ap_database.insert_sta_to_database(ap)

    def add_worker(self, worker):
        self.workers.append(worker)

    def on_ctrl_iface_data(self, fd, mask, arg):
        if mask != eloop.EVENT_READ:
            return

        msg = fd.recv(2048)
        print(msg)

    def _init_ctrl_iface(self):
        if os.path.exists(self.ctrl_path):
            os.unlink(self.ctrl_path)
        self.ctrl_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.ctrl_sock.setblocking(False)
        self.ctrl_sock.bind(self.ctrl_path)
        self.eloop.register(self.ctrl_sock, eloop.EVENT_READ, self.on_ctrl_iface_data)

    def start(self):
        for w in self.workers:
            w.init()
        self._init_ctrl_iface()
        self.eloop.run()


class SnifferWorker(object):

    def __init__(self, sniffer, ifname = None):
        self.ifname = ifname
        self.sock = None
        self.sniffer = sniffer
        sniffer.add_worker(self)
        self.eloop = sniffer.eloop
        self.current_channel = 1

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

    def on_raw_packet_received(self, fd, mask, arg):
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
        ssid = None
        if hasattr(data, "ssid"):
            ssid = data.ssid.data
        if hasattr(data, "ds"):
            channel = data.ds.ch
        bssid = data.mgmt.bssid
        # print("BEACON: bssid: %s, channel: %d, ssid: %s" % (self._to_mac_string(bssid), channel, ssid.decode('utf8')))
        self.sniffer.insert_ap_to_database(StationCache(bssid, time.monotonic(), ssid=ssid.decode('utf8')))
        # print(self.sniffer.ap_database)

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
            # print("MGMT: bssid: %s, sta_addr: %s" % (self._to_mac_string(bssid), self._to_mac_string(sta_addr)))
            self.sniffer.insert_sta_to_database(StationCache(sta_addr, time.monotonic()))

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
            # print("DATA: bssid: %s, sta_addr: %s" % (self._to_mac_string(bssid), self._to_mac_string(sta_addr)))

    def channel_switch(self, arg):
        self.current_channel += 1
        if self.current_channel > 14:
            self.current_channel = 1
        # print('switching channel to %d' % self.current_channel)
        os.system('iwconfig %s channel %d' % (self.ifname, self.current_channel))
        self.eloop.register_timeout(0.5, self.channel_switch)

    def init(self):
        self.create_raw_socket()
        self.eloop.register_timeout(0.5, self.channel_switch)
        self.eloop.register(self.sock, eloop.EVENT_READ, self.on_raw_packet_received)

        os.system('iwconfig %s channel %d' % (self.ifname, self.current_channel))


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
