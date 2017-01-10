#!/home/tiancj/python/py3k/bin/python

import heapq
import selectors
import time

# generic events, that must be mapped to implementation-specific ones
EVENT_READ = (1 << 0)
EVENT_WRITE = (1 << 1)


class EloopTimeout(object):

    __slots__ = ['scheduled', 'when', 'arg', 'callback']

    def __init__(self, when, callback, arg=None):
        self.when = when
        self.callback = callback
        self.arg = arg

    def __lt__(self, other):
        if self.when < other.when:
            return True
        return False

    def __le__(self, other):
        if self.when < other.when:
            return True
        return self.__eq__(other)

    def __gt__(self, other):
        if self.when > other.when:
            return True
        return False

    def __ge__(self, other):
        if self.when > other.when:
            return True
        return self.__eq__(other)

    def __eq__(self, other):
        return (self.when == other.when and
                self.callback == other.callback and
                self.arg == other.arg)

    def __ne__(self, other):
        return not self.__eq__(other)


class EventLoop(object):

    def __init__(self, sel=None):
        self._fd_to_key = {}
        self._timeouts = []
        self._sel = sel
        if sel is None:
            self._sel = selectors.DefaultSelector()

    def _time(self):
        return time.monotonic()

    def register(self, fileobj, events, data=None):
        self._sel.register(fileobj, events, data)

    def register_timeout(self, delay, callback, arg=None):
        timeout_event = EloopTimeout(delay + self._time(), callback, arg)
        heapq.heappush(self._timeouts, timeout_event)

    def unregister(self, fileobj):
        self._sel.unregister(fileobj)

    def run(self):
        """Perform the actual selection, until some monitored file objects are
        ready or a timeout expires.
        """
        while True:
            timeout = None
            timeout_handle = None
            if len(self._timeouts):
                timeout_handle = heapq.heappop(self._timeouts)
                timeout = max(0, timeout_handle.when - self._time())
            event_list = self._sel.select(timeout)
            for key, mask in event_list:
                callback = key.data
                callback(key.fileobj, mask)
            if timeout_handle:
                if self._time() >= timeout_handle.when:
                    callback = timeout_handle.callback
                    callback(timeout_handle.arg)


if __name__ == '__main__':

    def func1(arg):
        print("11111111")

    def func2(arg):
        print("22222222")


    print("eloop test")

    loop = EventLoop()
    loop.register_timeout(0.1, func1)
    loop.register_timeout(5, func1)
    loop.register_timeout(10, func2)

    loop.run()