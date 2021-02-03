# A python packet sniffer for inbound/outbound TCP/UDP packets.
# An exercise for practicing python and packet study.
from scapy.layers.inet import IP, UDP, TCP
from scapy.sendrecv import sniff
from geoip import geolite2
from pyfiglet import print_figlet
import socket
import datetime


# Launch function for the packet sniffer.
# Modified version of the function that appears in the Python Port Scanner project.
def launch_function():
    while True:
        try:
            choice = input("Start Packet Sniffer (Y/N): ")
            if choice == "Y":
                print("\n")
                # Calls the packet sniffer function.
                sniff(prn=packet_information)
            elif choice == "N":
                break
            # Used in case user inputs invalid option. Catches the issue and restarts the while.
            else:
                print("Not a valid option.")
                print("Restarting! \n")
                continue
        # Measure to ensure any unknown error is caught and restarts the while. At time of creation, no other errors
        # are known. This exists as a precaution.
        except Exception as e:
            print(e)
            print("Restarting! \n")
            continue
        else:
            break


# Printer for the packet data.
def printer(current_time, packet_format, source_mac, destination_mac, source_port, destination_port, source_ip,
            destination_ip, packet_timezone):
    print(str("[") + str(current_time) + str("]") + " " + str(packet_format) + " Bytes" + " " + "SRC-MAC:" +
          str(source_mac) + " " + "DST-MAC:" + str(destination_mac) + " " + "SRC-PORT:" + str(source_port) +
          " " + "DST-PORT:" + str(destination_port) + " " + "SRC-IP:" + str(source_ip) + " " + "DST-IP:" +
          str(destination_ip) + " " + "Location:" + packet_timezone)


# Function to gather key packet data.
def packet_information(target):
    current_time = datetime.datetime.now()
    # Variable packet_timezone is set as "N/A" due to an attribute error that can occur with packets that
    # do not contain a timezone attribute.
    packet_timezone = "N/A"

    try:
        # Target.haslayer(IP) if statement prevents an IndexError stating Layer[IP] not found.
        if target.haslayer(IP):
            # Target.haslayer(TCP/UDP) if/elif/else statements are used to determine which type of packet is being
            # sniffed. Checking the packet type here reduces complexity in other sections. Only TCP/UDP packets result
            # in valid being true because this program only sniffs TCP/UDP packets.
            if target.haslayer(TCP):
                valid = True
                # If/else statements determine if the packet is an inbound or outbound TCP packet and find the
                # packets size in bytes.
                if socket.gethostbyname(socket.gethostname()) == target[IP].dst:
                    packet_format = "TCP-IN:{}".format(len(target[TCP]))
                else:
                    packet_format = "TCP-OUT:{}".format(len(target[TCP]))
            elif target.haslayer(UDP):
                valid = True
                # If/else statements determine if the packet is an inbound or outbound UDP packet and find the
                # packets size in bytes. These statements have the same function as their TCP counterparts.
                if socket.gethostbyname(socket.gethostname()) == target[IP].dst:
                    packet_format = "UDP-IN:{}".format(len(target[UDP]))
                else:
                    packet_format = "UDP-OUT:{}".format(len(target[UDP]))
            else:
                valid = False

            # Section saves the various attributes of a packet to variables and calls the print function.
            if valid:
                source_mac = target.src
                destination_mac = target.dst
                source_ip = target[IP].src
                destination_ip = target[IP].dst
                source_port = target.sport
                destination_port = target.dport
                # Try/except is necessary to catch an AttributeError that occurs whenever a packet does not have
                # a location.
                try:
                    packet_timezone = geolite2.lookup(target[IP].src).timezone
                except AttributeError:
                    pass
                printer(current_time, packet_format, source_mac, destination_mac, source_port, destination_port,
                        source_ip, destination_ip, packet_timezone)
    # Except is intended to catch and print out any exception that was missed. At time of creation, no other errors
    # are known. This exists as a precaution.
    except IndexError:
        pass


if __name__ == '__main__':
    # Provides a welcome screen to the packet sniffer.
    colors = "95;197;220:"
    print_figlet("Packet Sniffer", font='slant', colors=colors)
    print("Welcome to a Python Packet Sniffer \n")

    # Calls launch function
    launch_function()
