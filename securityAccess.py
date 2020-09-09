from scapy.all import *

load_contrib('isotp')
load_contrib('automotive.uds')

sock = ISOTPNativeSocket('slcan0', 0x6f1, 0x610, 0x10, 0xf1, basecls=UDS)

a = sock.sr1(UDS()/UDS_DSC(diagnosticSessionType=0x3), verbose=False)
a.show()

x = sock.sr1(UDS()/UDS_SA(securityAccessType=0x3), verbose=False)
x.show()

# send key auth...