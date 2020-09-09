from scapy.all import load_contrib, load_layer
from scapy.layers.can import CAN
from scapy.contrib.isotp import ISOTPHeader, ISOTP_FF, ISOTPHeaderEA
from scapy.contrib.cansocket import CANSocket
from termcolor import colored
import sys
import threading
import time


# Keep awake thread
class keep_awake_thread(threading.Thread):
    def __init__(self, pkt):
        self.pkt = pkt
        threading.Thread.__init__(self)

    def run(self):
        keep_awake(self.pkt)


# Keep awake function
def keep_awake(pkt):
    global CanSocket_keep_awake, scan_done

    while not scan_done:
        CanSocket_keep_awake.send(pkt)
        time.sleep(0.5)


# Save background noise
def get_background_noise(noise_packet):
    global noise_IDs
    noise_IDs.append(noise_packet.identifier)


# Send multiple packets at once
# NOT USED
def send_multiple(startID, endID, paket, number_of_packets):
    if (startID + number_of_packets) <= endID:
        endID = startID + number_of_packets
    else:
        endID = endID + 1
    for i in range(startID, endID):
        paket.identifier = i
        CanSocket_communication.send(paket)


# This function is used for scanning with extended ID's.
# It sends multiple packets at once. The number of packets
# is defined in the global 'load' variable.
# It only changes the extended ID, NOT the actual ID of the packet.
def send_multiple_ext(extID, paket, number_of_packets):
    if (extID + number_of_packets) < 255:
        endID = extID + number_of_packets
        for i in range(extID, endID + 1):
            paket.extended_address = i
            CanSocket_communication.send(paket)
    else:
        endID = 255
        for i in range(extID, endID + 1):
            paket.extended_address = i
            CanSocket_communication.send(paket)


# ISOTP-Filter for periodic packets
def filter_periodic_packets(paketlist):
    received_IDs = {}
    duplicated_IDs = {}
    delete_list = []

    for pkt in paketlist:
        newID = paketlist[pkt][1]
        # if ID is duplicate
        if newID in received_IDs:
            time_gap = int(paketlist[pkt][0].time * 1000) - received_IDs[newID]
            received_IDs[newID] = int(paketlist[pkt][0].time * 1000)
            # if ID is duplicated for the first time
            if newID not in duplicated_IDs:
                duplicated_IDs[newID] = (time_gap, 1)
            else:
                # if same time gap
                if ((duplicated_IDs[newID][0] == time_gap) or
                        (duplicated_IDs[newID][0] == (time_gap + 1)) or
                        (duplicated_IDs[newID][0] == (time_gap - 1))):
                    duplicated_IDs[newID] = (time_gap,
                                             duplicated_IDs[newID][1] + 1)
                    # if 5 times same time gap
                    if (duplicated_IDs[newID][1] >= 3) and (pkt in paketlist):
                        delete_list.append(pkt)
        else:
            # save ID and timestamp
            received_IDs[newID] = int(paketlist[pkt][0].time * 1000)

    for i in delete_list:
        print(colored(str("delete " + hex(paketlist[i][1])), "yellow"))
        del paketlist[i]


# Scan for NOT extended ID's
def scan(min_ID, max_ID, pkt):
    for id in range(min_ID, max_ID + 1):
        def get_ISOTP_FC(packet):
            global found_packets

            # Filter background noise
            if (packet.identifier in noise_IDs):
                return
            # Filter extended IDs if not needed
            if (packet.identifier > 0x7FF) and not extended:
                return
            else:
                # if first nibble = 3 (FlowControl)
                if (int(packet.data[0]) >= 48 and int(packet.data[0] < 64)):
                    found_packets[id] = (packet, packet.identifier)

        pkt.identifier = id
        CanSocket_communication.sniff(prn=get_ISOTP_FC, timeout=0.2,
                                      started_callback=lambda:
                                      CanSocket_communication.send(pkt))
        time.sleep(0.5)


# Scan for extended ID's with binary search.
# Probably not useful because of the undefined
# behaviour of the recursive call of socket.sniff()
# NOT USED
def extended_scan_binsearch(min_ID, max_ID, ext_min, ext_max, load, pkt):
    def binary_search(min_ID, max_ID, ext_min, ext_max, load, pkt):
        if load == 0:
            load = 1
        for extID in range(ext_min, ext_max, load):

            def get_ISOTP_FC(packet):
                global found_packets
                # Filter background noise
                if (packet.identifier in noise_IDs):
                    return
                else:
                    # if first nibble = 3 (FlowControl)
                    if (int(packet.data[1]) >= 48 and
                            int(packet.data[1] < 64)):
                        if (extID == ext_max - 1):
                            full_ID = hex((id * 0x100) + extID)
                            found_packets[int(full_ID, 16)] = \
                                (packet, packet.identifier)
                        else:
                            if (extID + load) > 255:
                                binary_search(id, max_ID, extID,
                                              255, int(load / 2), pkt)
                            else:
                                binary_search(id, max_ID, extID,
                                              extID + load, int(load / 2), pkt)

            pkt.identifier = id
            CanSocket_communication.sniff(prn=get_ISOTP_FC, timeout=0.2,
                                          started_callback=send_multiple_ext(
                                              extID, pkt, load))

    for id in range(min_ID, max_ID + 1):
        binary_search(min_ID, max_ID, ext_min, ext_max, load, pkt)


# Fast scan with 'load' packages, remember ID's where an answer where found.
# If something found -> slow scan with single packages with extended ID 0 - 255
def extended_scan_iterating_search(min_ID, max_ID, load, pkt):

    def fast_search(load):
        id_list = []
        if load == 0:
            load = 1
        for extID in range(0, 256, load):

            def get_ISOTP_FC(packet):
                # Filter background noise and remote requests
                if (packet.identifier in noise_IDs or packet.flags != 0):
                    return
                else:
                    try:
                        # if first nibble = 3 (FlowControl)
                        if (int(packet.data[1]) >= 48 and
                                int(packet.data[1] < 64)):
                            id_list.append(extID)
                    except Exception:
                        print(colored(str("[!] Unknown message Exception: " +
                                          packet.__repr__()), "red"))

            # the sniff function actually only gets like 3
            # valid answer-packets out of the 100 packets (load)
            CanSocket_communication.sniff(prn=get_ISOTP_FC, timeout=0.3,
                                          started_callback=send_multiple_ext(
                                              extID, pkt, load))
            # without sleep it's to fast for the socket
            time.sleep(1)

        # remove duplicate ID's
        id_list = list(set(id_list))
        slow_search(id_list, load)

    def slow_search(id_list, load):
        for extID in id_list:
            if (extID + load) > 255:
                maxID = 255
            else:
                maxID = extID + load

            for extID1 in range(extID, maxID + 1):

                def get_ISOTP_FC(packet):
                    global found_packets

                    # if remote request
                    if packet.flags.value != 0:
                        return
                    else:
                        try:
                            # if first nibble = 3 (FlowControl)
                            if (int(packet.data[1]) >= 48 and
                                    int(packet.data[1] < 64)):
                                full_ID = hex((id * 0x100) + extID1)
                                found_packets[int(full_ID, 16)] = \
                                    (packet, packet.identifier)
                        except Exception:
                            print(colored(
                                str("[!] Unknown message Exception: " +
                                    packet.__repr__()), "red"))

                pkt.extended_address = extID1
                CanSocket_communication.sniff(prn=get_ISOTP_FC, timeout=0.2,
                                              started_callback=lambda:
                                              CanSocket_communication.
                                              send(pkt))
                time.sleep(0.5)

    for id in range(min_ID, max_ID + 1):
        pkt.identifier = id
        fast_search(load)


load_contrib("isotp")
load_contrib("cansocket")
load_layer("can")

extended = False
scan_done = False
awake_interface = False
extended_only = False
# Dictionary with Send-to-ID as key and a tuple (received packet, Recv_ID)
found_packets = {}
# List with paket-IDs of background noise packets
noise_IDs = []
# Seconds to listen to noise
noise_listen_time = 6
# Number of pakets send in a single blow
extended_load = 100

# CAN-ID Range
min_ID = int(sys.argv[1], 16)
max_ID = int(sys.argv[2], 16)

# Get arguments
args = []
for i in range(0, len(sys.argv)):
    args.append(sys.argv[i])
if "-e" in args:
    extended = True
if "-k" in args:
    awake_interface = True
if "-eo" in args:
    extended_only = True

dummy_pkt = CAN(identifier=0x123, data=b'\xaa\xff\xff\xff\xff\xff\xff\xee')

# Interface
CanSocket_communication = CANSocket("can1")

# Keep ECU awake
if awake_interface:
    CanSocket_keep_awake = CANSocket("can0")
    awake_thread = keep_awake_thread(dummy_pkt)
    awake_thread.start()

# Listen for default messages on CAN-bus
print("Filtering background noise...")
CanSocket_communication.sniff(prn=get_background_noise,
                              timeout=noise_listen_time,
                              started_callback=lambda:
                              CanSocket_communication.send(dummy_pkt))

# scan with normal ID's
if not extended_only:
    # Build random ISOTP-FirstFrame Packet
    pkt = ISOTPHeader() / ISOTP_FF()
    pkt.identifier = 0x0
    pkt.message_size = 100
    pkt.data = b'\x00\x00\x00\x00\x00\x00'
    print("Start scan (" + hex(min_ID) + " - " + hex(max_ID) + ")")

    scan(min_ID, max_ID, pkt)

# scan with extended ID's
if extended or extended_only:
    pkt = ISOTPHeaderEA() / ISOTP_FF()
    pkt.identifier = 0x0
    pkt.message_size = 100
    pkt.extended_address = 0
    pkt.data = b'\x00\x00\x00\x00\x00'

    print("Start scan with extended ID's (" + hex(min_ID) +
          " - " + hex(max_ID) + ")")
    extended_scan_iterating_search(min_ID, max_ID, extended_load, pkt)

# Stop "stay awake"-traffic
scan_done = True

filter_periodic_packets(found_packets)

# Print result
if (len(found_packets)) != 0:
    print(colored(str("\nFound " + str(len(found_packets)) +
                      " ISOTP-FlowControl Packet(s):"), "green"))
    for pack in found_packets:
        # if extended ID
        if (pack > 0x2FF):
            send_ID = int(pack / 256)
            send_ext = pack - (send_ID * 256)
            ext_ID = hex(found_packets[pack][0].data[0])
            print("\nSend to ID:\t\t\t\t" + hex(send_ID) +
                  "\nSend to extended ID:\t" + hex(send_ext) +
                  "\nReceived ID:\t\t\t" +
                  hex(found_packets[pack][0].identifier) +
                  "\nReceived extended ID:\t" + ext_ID + "\nMessage:\t\t\t\t" +
                  found_packets[pack][0].__repr__())
        else:
            print("\nSend to ID:\t\t" + hex(pack) + "\nReceived ID:\t" +
                  hex(found_packets[pack][0].identifier) +
                  "\nMessage:\t\t" + found_packets[pack][0].__repr__())

        # if padding
        if (found_packets[pack][0].length == 8):
            print("Padding enabled")
        else:
            print("No Padding")
else:
    print(colored("No packets found", "red"))