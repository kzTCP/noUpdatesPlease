from scapy.all import *
import psutil
from collections import defaultdict
import os
from threading import Thread
import pandas as pd

# get the all network adapter's MAC addresses
all_macs = {iface.mac for iface in ifaces.values()}
# A dictionary to map each connection to its correponding process ID (PID)
connection2pid = {}
# A dictionary to map each process ID (PID) to total Upload (0) and Download (1) traffic
pid2traffic = defaultdict(lambda: [0, 0])
# the global Pandas DataFrame that's used to track previous traffic stats
global_data_frame = None
# global boolean for status of the program
is_program_running = True

debug = True

#3376 windows update
list_task_to_end = [
    "SearchUI.exe", "updater.exe", "BackgroundDownload.exe"
]



def get_size(bytes):

    """
    Returns size of bytes in a nice format
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024


def process_packet(packet):

    global pid2traffic

    try:
        # get the packet source & destination IP addresses and ports
        packet_connection = (packet.sport, packet.dport)
    except (AttributeError, IndexError):
        # sometimes the packet does not have TCP/UDP layers, we just ignore these packets
        pass
        if debug: print("process_packet(): except")
    else:
        # get the PID responsible for this connection from our `connection2pid` global dictionary
        packet_pid = connection2pid.get(packet_connection)
        if packet_pid:
            if packet.src in all_macs:
                # the source MAC address of the packet is our MAC address
                # so it's an outgoing packet, meaning it's upload
                pid2traffic[packet_pid][0] += len(packet)
            else:
                # incoming packet, download
                pid2traffic[packet_pid][1] += len(packet)


def get_connections():

    """A function that keeps listening for connections on this machine 
    and adds them to `connection2pid` global variable"""

    global connection2pid

    # while is_program_running:
    while is_program_running:

        # using psutil, we can grab each connection's source and destination ports
        # and their process ID
        for c in psutil.net_connections():

            if c.laddr and c.raddr and c.pid:
                # if local address, remote address and PID are in the connection
                # add them to our global dictionary
                connection2pid[(c.laddr.port, c.raddr.port)] = c.pid
                connection2pid[(c.raddr.port, c.laddr.port)] = c.pid
                
        # sleep for a second, feel free to adjust this
        time.sleep(1)


def print_pid2traffic():

    global global_data_frame
    # initialize the list of processes
    processes = []

    for pid, traffic in list(pid2traffic.items()):

        # `pid` is an integer that represents the process ID
        # `traffic` is a list of two values: total Upload and Download size in bytes
        try:
            # get the process object from psutil
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:

            if debug:  print("continue")
            # if process is not found, simply continue to the next PID for now
            continue

        # get the name of the process, such as chrome.exe, etc.
        name = p.name()

        # get the time the process was spawned
        try:

            create_time = datetime.fromtimestamp(p.create_time())

        except OSError:

            # system processes, using boot time instead
            create_time = datetime.fromtimestamp(psutil.boot_time())

            if debug: print("create_time", create_time)

        # construct our dictionary that stores process info
        process = {
            "pid": pid, "name": name, "create_time": create_time, "Upload": traffic[0],
            "Download": traffic[1],
        }

        try:

            """ 
                `taskkill /im myprocess.exe /f`
            The "/f" is for "force". If you know the PID, then you can specify that, as in:

                `taskkill /pid 1234 /f`
            Lots of other options are possible, just type taskkill /? for all of them. 
            The "/t" option kills a process and any child processes; 
            that may be useful to you.
            """

            task_exists = list_task_to_end.index(name) != -1
            if task_exists:
                os.system(f"taskkill /f /im  {name}")
                print(f'task  {name} was killed')

        except Exception as e:
            # print("task not found")
            pass

        try:

            # calculate the upload and download speeds by simply subtracting the old stats from the new stats
            process["Upload Speed"] = traffic[0] - global_data_frame.at[pid, "Upload"]
            process["Download Speed"] = traffic[1] - global_data_frame.at[pid, "Download"]

        except (KeyError, AttributeError):
            # If it's the first time running this function, then the speed is the current traffic
            # You can think of it as if old traffic is 0
            process["Upload Speed"] = traffic[0]
            process["Download Speed"] = traffic[1]

            if debug: print("create_time", process)

        # append the process to our processes list
        processes.append(process)

    # construct our Pandas DataFrame
    data_frame = pd.DataFrame(processes)

    try:

        # set the PID as the index of the dataframe
        data_frame = data_frame.set_index("pid")
        # sort by column, feel free to edit this column
        data_frame.sort_values("Download", inplace=True, ascending=False)

    except KeyError as e:
        # when dataframe is empty
        pass

        if debug: print("pass")

    # make another copy of the dataframe just for fancy printing
    printing_data_frame = data_frame.copy()

    try:

        # apply the function get_size to scale the stats like '532.6KB/s', etc.
        printing_data_frame["Download"] = printing_data_frame["Download"].apply(get_size)
        printing_data_frame["Upload"] = printing_data_frame["Upload"].apply(get_size)
        printing_data_frame["Download Speed"] = printing_data_frame["Download Speed"].apply(get_size).apply(lambda s: f"{s}/s")
        printing_data_frame["Upload Speed"] = printing_data_frame["Upload Speed"].apply(get_size).apply(lambda s: f"{s}/s")

    except KeyError as e:
        # when dataframe is empty again
        pass
        if debug: print("pass 2")

    # clear the screen based on your OS
    os.system("cls") if "nt" in os.name else os.system("clear")

    # print our dataframe
    print("dataFrame:")
    print(printing_data_frame.to_string())

    # update the global df to our dataframe
    global_data_frame = data_frame


def print_stats():

    """Simple function that keeps printing the stats"""
    # while is_program_running:
    while is_program_running:
        time.sleep(1)
        print_pid2traffic()


if __name__ == "__main__":


    # start the printing thread
    printing_thread = Thread(target=print_stats)
    printing_thread.start()

    # start the get_connections() function to update the current connections of this machine
    connections_thread = Thread(target=get_connections)
    connections_thread.start()

    # start sniffing
    if debug: print("Started sniffing")
    sniff(prn=process_packet, store=False)
    # setting the global variable to False to exit the program
    is_program_running = False   