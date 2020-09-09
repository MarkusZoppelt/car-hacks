#!/usr/bin/env python
# coding: utf-8

from scapy.all import *
load_contrib('cansocket')
load_layer('can')
load_contrib('isotp')
load_contrib('automotive.uds')

gatewaySocket = ISOTPNativeSocket('slcan0', 0x6f1, 0x610, 0x10, 0xf1, basecls=UDS)
bodyDomainControllerSocket = ISOTPNativeSocket('slcan0', 0x6f1, 0x640, 0x40, 0xf1, basecls=UDS)

class DEVJOB(Packet):
    fields_desc=[
        ShortField('JobID', 0xFFFF) # development job identifier (dump memory)
    ]    

class WEBSERVER(Packet):
    fields_desc=[
        ByteField('Control', 1),
        StrFixedLenField('Key', b'164', length=3)
    ]

class READ_MEM(Packet):
    fields_desc=[
        IntField('read_addr', 0),
        IntField('read_length', 0)
    ]
    

# UDS.services[OxBF] = 'DevelopmentJob'

# 0xBF ist Service für development jobs
bind_layers(UDS, DEVJOB, service=0xBF)

bind_layers(DEVJOB, READ_MEM, JobID=0xFFFF)
bind_layers(DEVJOB, WEBSERVER, JobID=0xFF66)

pkt = UDS()/DEVJOB()/READ_MEM(read_addr=0x000, read_length=1024)

x = gatewaySocket.sr1(pkt, timeout=1)
pkt.show()
x.show()
hexdump(x)

pkt2 = UDS()/DEVJOB()/WEBSERVER()
y = gatewaySocket.sr1(pkt2, timeout=1)
pkt2.show()
y.show()

