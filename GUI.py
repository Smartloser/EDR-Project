from tkinter import Tk, Label
from multiprocessing import Process, Queue

class EdrGui(Process):

    def __init__(self, gui_queue: Queue):
        super(EdrGui, self).__init__()
        self.gui_queue = gui_queue

    def update_label(self, text):
        self.label['text'] += f"{text}\n"

    def update_loop(self):
        while True:
            text = self.gui_queue.get(block=True)
            self.update_label(text)

    def run(self):
        self.gui = Tk(className="Active Scanner")
        self.gui.geometry("700x400")
        self.gui.configure(background='black')

        self.label = Label(self.gui,
                        text="",
                        background='black',
                        fg='white',
                        font='arial')
        self.label.pack(side='top', anchor='nw')
        self.gui.after(1000, self.update_loop)
        self.gui.mainloop()