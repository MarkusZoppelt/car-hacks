#!/usr/bin/env python
# coding: utf-8

from scapy.all import *
load_contrib('cansocket')
load_layer('can')
load_contrib('isotp')

socket = CANSocket(iface='slcan0')

packet = CAN(identifier=0x7df, data=b'\x02\x11\x01')

response = socket.sr1(packet, timeout=1)

packet.show()
