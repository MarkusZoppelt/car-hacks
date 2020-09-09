#!/usr/bin/env python
# coding: utf-8

from scapy.all import *
load_contrib('cansocket')
load_layer('can')
load_contrib('isotp')
load_contrib('automotive.uds')
import argparse

gatewaySocket = ISOTPNativeSocket('slcan0', 0x6f1, 0x610, 0x10, 0xf1, basecls=UDS)
bodyDomainControllerSocket = ISOTPNativeSocket('slcan0', 0x6f1, 0x640, 0x40, 0xf1, basecls=UDS)

class DEVJOB(Packet):
    fields_desc=[
        ShortField('JobID', 0xFFFF) # development job identifier (dump memory)
    ]    

class READ_MEM(Packet):
    fields_desc=[
        IntField('read_addr', 0),
        IntField('read_length', 0)
    ]
    
bind_layers(UDS, DEVJOB, service=0xBF)
bind_layers(DEVJOB, READ_MEM, JobID=0xFFFF)

def dumpMemoryAtAddressWithLength(socket, addr, length):
    pkt = UDS()/DEVJOB()/READ_MEM(read_addr=addr, read_length=length)
    x = socket.sr1(pkt, timeout=1)
    pkt.show()
    x.show()
    # hexdump(x)

dumpMemoryAtAddressWithLength(gatewaySocket, 0, 2048+900)




