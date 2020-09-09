#!/usr/bin/env python
# coding: utf-8

from scapy.all import *
load_contrib('isotp')
load_contrib('automotive.uds')

gatewaySocket = ISOTPNativeSocket('slcan0', 0x6f1, 0x610, 0x10, 0xf1, basecls=UDS)
bodyDomainControllerSocket = ISOTPNativeSocket('slcan0', 0x6f1, 0x640, 0x40, 0xf1, basecls=UDS)

pkt = UDS()/UDS_DSC(diagnosticSessionControl=3)
gatewaySocket.sr1(pkt)
bodyDomainControllerSocket.sr1(pkt)

def discoverSocket(socket, minID, maxID):
for i in range(minID, maxID):
    pkt = UDS()/UDS_RDBI(identifiers=[i]) # example: 0x170
    x = socket.sr1(pkt, timeout=2, verbose=False)
    if x.service != 0x7f:
        print(x.__repr__())
        # pkt.show()
        # x.show()

discoverSocket(bodyDomainControllerSocket, 0xf27, 0xffff)
