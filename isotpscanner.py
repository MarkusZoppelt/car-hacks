from scapy.all import load_contrib, load_layer
from scapy.layers.can import CAN
from scapy.contrib.isotp import ISOTPHeader, ISOTP_FF, ISOTPHeaderEA
from scapy.contrib.cansocket import CANSocket
import argparse
from termcolor import colored
from scanners import isotpscan

load_layer("can")
load_contrib("isotp")
load_contrib("cansocket")


# Save background noises
def get_background_noise_callback(noise_packet):
    global noise_IDs
    noise_IDs.append(noise_packet.identifier)


def get_isotp_packet(type=None):
    if type == "extended":
        pkt = ISOTPHeaderEA() / ISOTP_FF()
        pkt.extended_address = 0
        pkt.data = b'\x00\x00\x00\x00\x00'
    else:
        pkt = ISOTPHeader() / ISOTP_FF()
        pkt.data = b'\x00\x00\x00\x00\x00\x00'

    pkt.identifier = 0x0
    pkt.message_size = 100
    return pkt


# Get arguments
def get_Args():
    parser = argparse.ArgumentParser(description="Scan for active "
                                     "ISOTP-Addresses.",
                                     prog="ISOTP Scanner",
                                     usage="isotpscanner.py StartID EndID "
                                     "Interface [-flags]")
    parser.add_argument("StartID", type=get_start_ID, nargs=1,
                        help="Start scan at this ID (hex)")
    parser.add_argument("EndID", type=get_end_ID, nargs=1,
                        help="End scan at this ID (hex)")
    parser.add_argument("Interface", type=str,
                        help="CAN interface for the scan")
    parser.add_argument("-e", "--extended", action="store_true",
                        help="Include extended ID's to scan.")
    parser.add_argument("-k", type=str,
                        help="'Keep alive' - \
                        Send a periodic dummy-packet to specified interface.")
    parser.add_argument("-eo", "--extended_only", action="store_true",
                        help="Scan only with \
                        extended ID's.")
    return parser.parse_args()


# Parse CAN-ID Range from arguments
def get_start_ID(x):
    global min_ID
    min_ID = int(x, 16)


def get_end_ID(x):
    global max_ID
    max_ID = int(x, 16)


extended = False
scan_done = False
keep_awake = False
extended_only = False
awake_interface = ""
min_ID = 0x0
max_ID = 0x0

args = get_Args()

scan_interface = args.Interface
if args.extended:
    extended = True
if args.extended_only:
    extended_only = True
if args.k:
    keep_awake = True
    awake_interface = args.k

# Dictionary with Send-to-ID as key and a tuple (received packet, Recv_ID)
found_packets = {}
# List with paket-IDs of background noise packets
noise_IDs = []
# Seconds to listen to noise
noise_listen_time = 10
# Number of pakets send in a single blow
extended_load = 100

dummy_pkt = CAN(identifier=0x123, data=b'\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb')

# Interface for communication
CanSocket_communication = CANSocket(scan_interface)

# Keep ECU awake
if keep_awake:
    CanSocket_keep_awake = CANSocket(awake_interface)
    awake_thread = isotpscan.KeepAwakeThread(CanSocket_keep_awake,
                                             dummy_pkt)
    awake_thread.start()

# Listen for default messages on CAN-bus
print("Filtering background noise...")
CanSocket_communication.sniff(prn=get_background_noise_callback,
                              timeout=noise_listen_time,
                              started_callback=lambda:
                              CanSocket_communication.send(dummy_pkt))

# delete duplicates
noise_IDs = list(set(noise_IDs))

# scan normal ID's
if not extended_only:
    # Build random ISOTP-FirstFrame Packet
    pkt = get_isotp_packet()

    print("Start scan (" + hex(min_ID) + " - " + hex(max_ID) + ")")

    isotpscan.scan(found_packets, CanSocket_communication, range(min_ID,
                   (max_ID + 1)), pkt, noise_IDs)

# scan extended ID's
if extended or extended_only:
    pkt = get_isotp_packet("extended")

    print("Start scan with extended ID's (" + hex(min_ID) +
          " - " + hex(max_ID) + ")")

    isotpscan.scan_extended(found_packets, CanSocket_communication,
                            range(min_ID, (max_ID + 1)),
                            extended_load, pkt, noise_IDs)

# Stop "stay awake"-traffic
if keep_awake:
    awake_thread.stop()

isotpscan.filter_periodic_packets(found_packets)

# Print result
if (len(found_packets)) != 0:
    print(colored(str("\nFound " + str(len(found_packets)) +
                      " ISOTP-FlowControl Packet(s):"), "green"))
    for pack in found_packets:
        # if extended ID
        if (pack > 0xFFF):
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
            print("\nSend to ID:\t\t" + hex(pack) + "\nReceived ID:\t\t" +
                  hex(found_packets[pack][0].identifier) +
                  "\nMessage:\t\t" + found_packets[pack][0].__repr__())

        # if padding
        if (found_packets[pack][0].length == 8):
            print("Padding enabled")
        else:
            print("No Padding")
else:
    print(colored("No packets found", "red"))
