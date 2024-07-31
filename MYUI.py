
from tkinter import *
from scapy.all import *
from NoUpdates import NoUpdates


class MYUI:

    def __init__(self) -> None:
        self.window = Tk()
        self.window.title = "No Updates By KZCODE_"


    def on_exit(self, func=None):

        self.window.destroy()
        if func: func()


    def on_kill_btn_press(self, func=None):

        task = self.kill_entry.get()
        print("func", func)
        if func: func(task)

        self.kill_entry.delete(0, END)


    def build(self):
         
        self.frame = Frame(self.window)

        self.label = Label(self.frame, text="Task Name: ")
        self.label.pack(fill=BOTH, side=LEFT, expand=True, padx=10)

        self.kill_entry = Entry(self.frame)
        self.kill_entry.pack(fill=BOTH, side=LEFT, expand=True, padx=10)

        self.btn_kill = Button(self.frame, text="Kill", command=self.on_kill_btn_press)
        self.btn_kill.pack(fill=BOTH, side=LEFT, expand=True, padx=10)

        self.frame.pack(fill=BOTH, side=TOP, expand=True, pady=10)

        self.text_box = Text()
        self.text_box.pack(fill=BOTH, side=TOP, expand=True)

        self.window.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.window.mainloop()
    


if __name__ == "__main__":

    mu = MYUI()

    mu.build()

    def hi(g):

        print('hui', g)

    mu.on_kill_btn_press(hi)
