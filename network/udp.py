# -*- coding: utf-8 -*-

import time
import socket
import threading
import subprocess


class UdpPeer(object):
    def __init__(self):
        self.__RX_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.__TX_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__TX_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # broadcast settings
        self.__TX_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # broadcast settings

        self.verbose = True
        self.__on_read = None
        self.__pack = lambda data: data
        self.__unpack = lambda data: data
        self.port = None

        self.local_ips = subprocess.check_output(['hostname', '--all-ip-addresses'])
        self.local_ips = bytes(self.local_ips).decode()
        self.local_ips = self.local_ips.split("\n")
        self.local_ips.remove("")

        def reader():
            while True:
                packed_data, (ip, port) = self.__RX_socket.recvfrom(4096)

                if not self.verbose and ip in self.local_ips:
                    return

                data = self.__unpack(packed_data)
                data = bytes(data).decode()

                if self.verbose:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                    print("RX {0:>15}:{1:<5} {2}\n\tUNPACKED= {3}\n\tRAW= {4}\n\n".format(ip, port, timestamp, data, packed_data))

                if self.__on_read:
                    self.__on_read((ip, port), data)

        self.__readingThread = threading.Thread(target=reader)
        self.__readingThread.daemon = True

    def __read(self, on_read_callback):
        self.__on_read = on_read_callback

    def __before_send(self, pack_callback):
        self.__pack = pack_callback

    def __after_receive(self, unpack_callback):
        self.__unpack = unpack_callback

    def bind(self, port):
        self.port = port
        self.__RX_socket.bind(("", self.port))
        self.__readingThread.start()

    def write(self, address, data):
        ip = address[0]
        port = address[1] if len(address) == 2 else self.port

        packed_data = str(data).encode()
        packed_data = self.__pack(packed_data)

        if self.verbose:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            print("TX {0:>15}:{1:<5} {2}\n\tRAW= {3}\n\tPACKED= {4}\n\n".format(ip, port, timestamp, data, packed_data))

        self.__TX_socket.sendto(packed_data, (ip, port))

    def broadcast(self, address, data):
        ip = address[0] if address else "255.255.255.255"
        port = address[1] if address and len(address) == 2 else self.port

        self.write((ip, port), data)

    onRead = property(fset=__read)

    pack = property(fset=__before_send)
    unpack = property(fset=__after_receive)


if __name__ == "__main__":

    import sys
    import signal

    from network.udp import UdpPeer

    def onRead(address, data):
        print("RX: {} {}".format(str(address), data))

    VERBOSE = True

    try:
        peer = UdpPeer()
        peer.verbose = VERBOSE
        peer.bind(7591)
        peer.onRead = onRead

        for idx in range(10):
            time.sleep(1)

            data = "Hello there"
            # peer.write(("192.168.98.61", 7591), data)
            peer.broadcast((), data)

        signal.pause()
        print("Here")

    except KeyboardInterrupt:
        sys.exit(0)

    except RuntimeError as error:
        sys.stderr.write(str(error))
        sys.exit(1)

