import socket
import eloop
import dpkt


class Transport(object):
    mac_interval = 30
    sta_mac_interval = 30
    ap_mac_interval = 30
    vid_interval = 60
    heartbeat_interval = 60
    period_interval = 1

    def __init__(self, loop):
        self.eloop = loop

    def send_mac(self, arg):
        self.eloop.register_timeout(self.mac_interval, self.send_mac)

    def send_sta_mac(self, arg):
        self.eloop.register_timeout(self.sta_mac_interval, self.send_sta_mac)

    def send_ap_mac(self, arg):
        self.eloop.register_timeout(self.ap_mac_interval, self.send_ap_mac)

    def heartbeat(self, arg):
        self.eloop.register_timeout(self.heartbeat_interval, self.heartbeat)

    def send_vid(self, arg):
        self.eloop.register_timeout(self.vid_interval, self.send_vid)

    def period_check(self, arg):
        self.eloop.register_timeout(self.period_interval, self.period_check)

    def run(self):
        self.eloop.register_timeout(self.mac_interval, self.send_mac)
        self.eloop.register_timeout(self.sta_mac_interval, self.send_sta_mac)
        self.eloop.register_timeout(self.ap_mac_interval, self.send_ap_mac)
        self.eloop.register_timeout(self.vid_interval, self.send_vid)
        self.eloop.register_timeout(self.heartbeat_interval, self.heartbeat)
        self.eloop.register_timeout(self.period_interval, self.period_check)


class DefaultTransport(Transport):

    mac_interval = 5

    MSG_START_REQ = 0x0A01
    MSG_START_ACK = 0x0A02
    MSG_HEARTBEAT_REQ = 0x0A03
    MSG_KEEP_ALIVE_ACK = 0x0A04
    MSG_WIFI_MAC_REPORT = 0x0A05
    MSG_WIFI_MAC_REPORT_ACK = 0X0A06
    MSG_WIFI_VIR_DATA_REPORT = 0x0A07
    MSG_RUN_STAT_REPORT = 0x0A08
    MSG_SET_DATETIME_REQ = 0x0A10
    MSG_SET_DATETIME_ACK = 0x0A11

    def __init__(self, el):
        super().__init__(el)
        self.sendbuf = b''
        self.recvbuf = b''

    def write(self, buf):
        self.sendbuf += buf
        if self.sendbuf:
            self.eloop.modify(self.sock, eloop.EVENT_READ | eloop.EVENT_WRITE, self._on_socket_event)

    def send_mac(self, arg):
        super().send_mac(arg)
        print('send_mac')

    def _on_socket_event(self, fd, mask, arg):
        if mask & eloop.EVENT_READ:
            print("read buffer")
            buf = fd.recv(4096)
            # self.recvbuf += buf
            print(buf)

        if mask & eloop.EVENT_WRITE:
            if self.sendbuf:
                print("write buffer")
                r = fd.send(self.sendbuf)
                if r > 0:
                    self.sendbuf = self.sendbuf[r:]
            else:
                self.eloop.modify(fd, eloop.EVENT_READ, self._on_socket_event)

    def _start_req(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(False)
        self.eloop.register(self.sock, eloop.EVENT_READ | eloop.EVENT_WRITE, self._on_socket_event)
        try:
            self.sock.connect(('123.57.90.192', 10002))
        except BlockingIOError as e:
            pass
        body = self.MsgStartReq()
        body.datas = b'20160112 1757'
        hdr = self.CmdHdr(data=body.pack())
        hdr.len = hdr.__hdr_len__ + len(body)
        hdr.magic_code = 0
        hdr.msg_type = self.MSG_START_REQ
        self.write(hdr.pack())
        print(hdr.pack())

    def run(self):
        super().run()
        self._start_req()

    class CmdHdr(dpkt.Packet):
        __byte_order__ = '!'
        __hdr__ = (
            ('magic_code', 'I', 0),
            ('msg_type', 'I', 0),
            ('len', 'I', 0)
        )

    class MsgStartReq(dpkt.Packet):
        __byte_order__ = '!'
        __hdr__ = (
            ('deviceId', 'I', 0),
            ('phyId', 'I', 0),
            ('version', 'H', 0),
            ('datas', '20s', 0)
        )
