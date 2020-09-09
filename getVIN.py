#!/usr/bin/env python
# coding: utf-8

from scapy.all import *
load_contrib('cansocket')
load_layer('can')
load_contrib('isotp')
load_contrib('automotive.uds')

gatewaySocket = ISOTPNativeSocket('slcan0', 0x6f1, 0x610, 0x10, 0xf1, basecls=UDS)

pkt = UDS()/UDS_RDBI(identifiers=0xf190)
x = gatewaySocket.sr1(pkt, timeout=2, verbose=False)
if x.service != 0x7f:
    # print(x.__repr__())
    # pkt.show()
    x.show()
