from scapy.all import *
import psutil
from collections import defaultdict
import os
from threading import Thread
import pandas as pd
from tkinter import *
from PIL import ImageTk, Image

from MYFileManager import MYFileManager


class NoUpdates:


    def __init__(self, ) -> None:
        
        # get the all network adapter's MAC addresses
        self.all_macs = {iface.mac for iface in ifaces.values()}
        # A dictionary to map each connection to its correponding process ID (PID)
        self.connection2pid = {}
        # A dictionary to map each process ID (PID) to total Upload (0) and Download (1) traffic
        self.pid2traffic = defaultdict(lambda: [0, 0])
        # the global Pandas DataFrame that's used to track previous traffic stats
        self.global_data_frame = None
        # global boolean for status of the program
        self.is_program_running = True

        self.debug = False

        self.icon_image =  None

        self.sleep_in_sc = 1



        #3376 windows update
        # SearchUI.exe == cortana + windows search bar
        
        self.mfm = MYFileManager()

        if  not self.mfm.read():
            self.mfm.append( "updater.exe")
            self.mfm.append( "BackgroundDownload.exe")
        
        self.list_task_to_end: list = self.mfm.read() 
        self.window = None
        self.text_box = None

        self.list_killed_tasks = None

 
    def get_size(self, bytes):

        """
        Returns size of bytes in a nice format
        """
        for unit in ['', 'K', 'M', 'G', 'T', 'P']:
            if bytes < 1024:
                return f"{bytes:.2f}{unit}B"
            bytes /= 1024


    def _process_packet(self, packet):

        if self.is_program_running:

            try:
                # get the packet source & destination IP addresses and ports
                packet_connection = (packet.sport, packet.dport)
            except (AttributeError, IndexError):
                # sometimes the packet does not have TCP/UDP layers, we just ignore these packets
                pass
                if self.debug: print("process_packet(): except")
            else:
                # get the PID responsible for this connection from our `connection2pid` global dictionary
                packet_pid =  self.connection2pid.get(packet_connection)
                if packet_pid:
                    if packet.src in  self.all_macs:
                        # the source MAC address of the packet is our MAC address
                        # so it's an outgoing packet, meaning it's upload
                        self.pid2traffic[packet_pid][0] += len(packet)
                    else:
                        # incoming packet, download
                        self.pid2traffic[packet_pid][1] += len(packet)

        else:
            if self.debug: print("process_packet")
            # exit() # force closing incase of an error


    def get_connections(self, ):

        """A function that keeps listening for connections on this machine 
        and adds them to `connection2pid` global variable"""

        # while is_program_running:
        while  self.is_program_running:

            # using psutil, we can grab each connection's source and destination ports
            # and their process ID
            for c in psutil.net_connections():

                if c.laddr and c.raddr and c.pid:
                    # if local address, remote address and PID are in the connection
                    # add them to our global dictionary
                    self.connection2pid[(c.laddr.port, c.raddr.port)] = c.pid
                    self.connection2pid[(c.raddr.port, c.laddr.port)] = c.pid
                    
            # sleep for a second, feel free to adjust this
            time.sleep(self.sleep_in_sc)


    def kill_task(self, name):

        try:

            """ 
                `taskkill /im myprocess.exe /f`
            The "/f" is for "force". If you know the PID, then you can specify that, as in:

                `taskkill /pid 1234 /f`
            Lots of other options are possible, just type taskkill /? for all of them. 
            The "/t" option kills a process and any child processes; 
            that may be useful to you.

           

            """

            task_exists =  self.list_task_to_end.index(name) != -1

            if task_exists:
                # os.system(f"taskkill /f /im  {name}")
                os.system(f"""wmic process where "name='{name}'" delete""")
                print(f'task  {name} was killed')

        except Exception as e:
            # print("task not found")
            pass


    def get_list_processes(self,) -> list:

        # initialize the list of processes
        processes = []

        for pid, traffic in list(self.pid2traffic.items()):

            # `pid` is an integer that represents the process ID
            # `traffic` is a list of two values: total Upload and Download size in bytes
            try:
                # get the process object from psutil
                p = psutil.Process(pid)
            except psutil.NoSuchProcess:

                if  self.debug:  print("continue")
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

                if  self.debug: print("create_time", create_time)

            # construct our dictionary that stores process info
            process = {
                "pid": pid, "name": name, "create_time": create_time, "Upload": traffic[0],
                "Download": traffic[1],
            }

            self.kill_task(name)

            try:

                # calculate the upload and download speeds by simply subtracting the old stats from the new stats
                process["Upload Speed"] = traffic[0] - self.global_data_frame.at[pid, "Upload"]
                process["Download Speed"] = traffic[1] - self.global_data_frame.at[pid, "Download"]

            except (KeyError, AttributeError):
                # If it's the first time running this function, then the speed is the current traffic
                # You can think of it as if old traffic is 0
                process["Upload Speed"] = traffic[0]
                process["Download Speed"] = traffic[1]

                if  self.debug: print("create_time", process)

            # append the process to our processes list
            processes.append(process)

        return processes


    def get_printable_data(self, ):
        
        processes = self.get_list_processes()
        # construct our Pandas DataFrame
        data_frame = pd.DataFrame(processes)

        try:

            # set the PID as the index of the dataframe
            data_frame = data_frame.set_index("pid")
            # sort by column, feel free to edit this column
            data_frame.sort_values("Download", inplace=True, ascending=False)

        except KeyError as e:
            # when data_frame is empty
            pass

            if  self.debug: print("pass")

        # make another copy of the data_frame just for fancy printing
        printing_data_frame = data_frame.copy()

        try:

            # apply the function get_size to scale the stats like '532.6KB/s', etc.
            printing_data_frame["Download"] = printing_data_frame["Download"].apply( self.get_size)
            printing_data_frame["Upload"] = printing_data_frame["Upload"].apply( self.get_size)
            printing_data_frame["Download Speed"] = printing_data_frame["Download Speed"].apply( self.get_size).apply(lambda s: f"{s}/s")
            printing_data_frame["Upload Speed"] = printing_data_frame["Upload Speed"].apply( self.get_size).apply(lambda s: f"{s}/s")

        except KeyError as e:
            # when data_frame is empty again
            if  self.debug: print("pass 2")


        # update the global df to our data_frame
        self.global_data_frame = data_frame

        return printing_data_frame


    def _app_loop_print(self, ):

        while  self.is_program_running:

            if self.text_box:
                time.sleep(self.sleep_in_sc)
                if self.is_program_running:
                    self.text_box.delete("1.0", END)
                    self.text_box.insert("1.0", self.get_printable_data().to_string())


    def quit_app(self, ):

        self.is_program_running = False  

        if self.list_killed_tasks:
            self.list_killed_tasks.destroy()
            self.list_killed_tasks = None

        if self.window:
            self.window.destroy()
            self.window = None
        

    def is_app_open(self): return self.window and self.is_program_running 


    def reset(self,):

        self.global_data_frame = None
        self.connection2pid = {}
        self.pid2traffic = defaultdict(lambda: [0, 0])


    def _on_kill_btn_press(self, ):

        if self.list_killed_tasks: 
            self.list_killed_tasks.destroy()
            self.list_killed_tasks = None

        if self.kill_entry.get():
            self.mfm.append(self.kill_entry.get())
            self.kill_entry.delete(0, END)
            self.reset()


    def _on_remove_btn_press(self, ):

        if self.list_killed_tasks: 
            self.list_killed_tasks.destroy()
            self.list_killed_tasks = None

        if self.kill_entry.get():
            self.mfm.remove(self.kill_entry.get())
            self.kill_entry.delete(0, END)
            self.reset()


    def _on_list_killed_tasks_exit(self, ):
        self.list_killed_tasks.destroy()
        self.list_killed_tasks = None


    def _on_show_list_btn_press(self, ):

        if not self.list_killed_tasks:

            self.list_killed_tasks = Tk()
            self.list_killed_tasks.geometry('800x400')
            self.list_killed_tasks.title("List Tasks To Kill")

            # self.list_killed_tasks.iconphoto(True,  self.icon_image)

            text_box = Text(   self.list_killed_tasks)
            text_box.pack(fill=BOTH, side=TOP, expand=True)

            for task in self.mfm.read():
                text_box.insert("1.0", task + "\n")
            
            self.list_killed_tasks.protocol("WM_DELETE_WINDOW", self._on_list_killed_tasks_exit)
            self.list_killed_tasks.mainloop()


    def _start_app_base(self):

        if self.is_program_running:

            self.window = Tk()
            self.window.geometry('800x400')
            self.window.title("NO UPDATES")

            self.icon_image = ImageTk.PhotoImage(Image.open(os.getcwd() + r"/imgs/refresh.png"))
            self.window.iconphoto(True, self.icon_image)

            self.frame = Frame(self.window)

            self.label = Label(self.frame, text="Task Name: ")
            self.label.pack(fill=BOTH, side=LEFT, expand=True, padx=10)

            self.kill_entry = Entry(self.frame)
            self.kill_entry.pack(fill=BOTH, side=LEFT, expand=True, padx=10)

            self.btn_kill = Button(self.frame, text="Kill", command=self._on_kill_btn_press)
            self.btn_kill.pack(fill=BOTH, side=LEFT, expand=True, padx=10)

            self.btn_remove = Button(self.frame, text="remove", command=self._on_remove_btn_press)
            self.btn_remove.pack(fill=BOTH, side=LEFT, expand=True, padx=10)

            self.btn_show_list = Button(self.frame, text="list", command=self._on_show_list_btn_press)
            self.btn_show_list.pack(fill=BOTH, side=LEFT, expand=True, padx=10)

            self.frame.pack(fill=BOTH, side=TOP, expand=True, pady=10)

            self.text_box = Text()
            self.text_box.pack(fill=BOTH, side=TOP, expand=True)
            
            self.window.protocol("WM_DELETE_WINDOW", self.quit_app)
            self.window.mainloop()


    def _sniff_stop_filter(self, packet):
        return not self.is_program_running
            

    def start_app(self, ):

        self.is_program_running = True

        self.app_thread = Thread(target=self._start_app_base)
        self.app_thread.start()
       
        self.printing_thread = Thread(target=self._app_loop_print)
        self.printing_thread.start()

        self.connections_thread = Thread(target=self.get_connections)
        self.connections_thread.start()

        # start sniffing
        if self.debug: print("Started sniffing")
        sniff(prn=self._process_packet, store=False,  stop_filter=self._sniff_stop_filter)
        # setting the global variable to False to exit the program
        self.is_program_running = False   




if __name__ == "__main__":

    tasks_to_end = [
        "updater.exe", "BackgroundDownload.exe"
    ]

    nu = NoUpdates()

    # nu.start_console(tasks_to_end)
    nu.start_app()

    
    #  pid   name   create_time   Upload  Download Upload Speed Download Speed
