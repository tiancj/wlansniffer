#!/home/tiancj/python/py3k/bin/python

import sys
import getopt


class Sniffer(object):
    def __init__(self):
        self.workers = []

    def add_worker(self, worker):
        self.workers.append(worker)


class SnifferWorker(object):
    def __init__(self, sniffer, ifname = None):
        self.ifname = ifname
        sniffer.add_worker(self)
        pass

    def __str__(self):
        return 'SnifferWorker: <ifname %s>' % self.ifname


def usage(program):
    print("Usage: %s [-i <ifname>]\n", program)

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


if __name__ == '__main__':
    main()