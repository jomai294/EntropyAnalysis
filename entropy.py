import Tkinter
from Tkinter import *
from ttk import *
import tkMessageBox
import time
import random
import Queue
import re
from PacketCapture import PacketCapture
from EntropyDataManager import EntropyDataManager
from tkFileDialog import askopenfilename
from tkFileDialog import asksaveasfilename
import socket
import threading

# CS160 Fall 2016 Project
# Project Name: Entropy Analysis
# Group Members: Frank Mock, Ben Sieben, Henry Spivey, John Mai, Dennis Dolorfo


# This program calculates Shannon's entropy on captured packets.
# EntropyGUI is the main GUI for this program. It uses a worker
# thread that captures packets and computes the entropy result.
# This allows the GUI to still respons to user events.
# The program will automatically determin the host IP. The user
# must enter the number of packets to analyze and then press
# the 'Capture' button. The entropy result will be displayed.
# The user can save the results that are displayed into a text
# file.
class EntropyGUI:
    def __init__(self, root, queue, endCommand, threadClient):
        
        # Reference to queue worker thread puts results in
        self.queue = queue
        
        # Reference to the worker thread
        self.tc = threadClient
        
        self.numPackets = ""
        self.host = ""
        
        root.title("Entropy Analysis")

        # Add drop down menu
        menubar = Menu(root)
        root.config(menu=menubar)

        # create a pulldown menu, and add it to the menu bar
        operationMenu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=operationMenu)
        operationMenu.add_command(label="Open",
                                  command=self.openFile)
        operationMenu.add_command(label="Save",
                                  command=self.saveFile)
        operationMenu.add_command(label='Exit', accelerator='Alt+F4', 
                                  command=self.exitProgram)
        
        # Add a frame to hold seperator
        frame0 = Frame(root) # Create and add a frame to window
        frame0.grid(row = 1, column = 1, sticky = W)
        
        # Add a frame to hold...
        frame1 = Frame(root) # Create and add a frame to window
        frame1.grid(row = 2, column = 1, sticky = W)
        
        # Add a frame to hold
        frame2 = Frame(root)
        frame2.grid(row = 3, column = 1, sticky = W)
        
        # Add a frame to hold padding row
        frame3 = Frame(root)
        frame3.grid(row = 4, column = 1, sticky = W)
        
        # Add a frame to hold textarea and scrollbar
        frame4 = Frame(root)
        frame4.grid(row = 5, column = 1, sticky = W)
        
        ##### Frame 0 Contents ####
        # Spacer
        Label(frame0, text=" ").grid(row=1, column=1, sticky=W)          
                
        ##### Frame 1 Contents ####
        Label(frame1, text="            ").grid(row=1, column=1, sticky=W)
        Label(frame1, text="Select Host IP").grid(row=1, column=2)
        Label(frame1, text="                       ").grid(row=1, column=3, sticky=W)
        Label(frame1, text="Number of Packets").grid(row=1, column=4, sticky=W)
        
        #### Frame 2 Contents ####
        Label(frame2, text="            ").grid(row=1, column=1, sticky=W)
        # Entrybox to get the host IP
        self.hostIP = StringVar()
        
        # Find all IP addresses connected to outside world
        ipAddresses = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)]
        
        # Take the IPv4 addresses only (packet capture code fails for IPv6 addresses)
        ipv4Addresses = []
        
        # regex to validate an IP address
        pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        
        # If address matches an IP address add it to ip4Addresses list
        for address in ipAddresses:
            if pattern.match(address) is not None:
                ipv4Addresses.append(address)
                
        # Place the IP addresses in the combo box       
        self.textEntry = Combobox(frame2, textvariable = self.hostIP, state = 'readonly', values = ipv4Addresses)
        self.textEntry.grid(row=1, column=2, sticky=W)
        self.textEntry.current(0)

        # Spacer
        Label(frame2, text=" ").grid(row=1, column=3, sticky=W)        
        
        # Enter number of packets to capture
        self.numPackts = StringVar()
        self.numPacktsEntry = Entry(frame2, textvariable = self.numPackts)
        self.numPacktsEntry.grid(row=1, column=4, sticky=W)
        
        # Spacer
        Label(frame2, text=" ").grid(row=1, column=5, sticky=W)
        
        # Button to trigger the packet capture
        button = Button(frame2)
        button.configure(text="Capture Packets")
        button.bind("<Button-1>", self.buttonClickCallback)
        button.grid(row=1, column=6, sticky='w')
        Label(frame2, text=" ").grid(row=1, column=7, sticky=W)  # Spacer
        
        # Button to cancel the packet capture
        cancelButton = Button(frame2)
        cancelButton.configure(text="Cancel")
        cancelButton.bind("<Button-1>", self.cancelButtonEvent)
        cancelButton.grid(row=1, column=8, sticky=W)
        
        #### Frame 3 Contents ####
        # Spacer
        Label(frame3, text="   ").grid(row=1, column=1, sticky=W)
        
        #### Frame 4 Contents ####
        # include a Scrollbar to connect to the Text where all the packets get printed
        scrollbar = Scrollbar(frame4)
        scrollbar.pack(side = RIGHT, fill = Y)
        #scrollbar.pack(side=RIGHT, fill=Y)

        self.textArea = Text(frame4)
        self.textArea.configure(width=90, height=35, wrap = WORD, yscrollcommand = scrollbar.set)
        self.textArea.pack()
        scrollbar.config(command=self.textArea.yview)


    # Callback method activated when the left mouse key clicks the 
    # "Capture Packet" button
    # Initiates capturing packets and getting and entropy result
    def buttonClickCallback(self, event):
        # Get the IP address selected
        self.host = self.textEntry.get()
        
        # Get the number of packets user requests
        self.numPackets = self.numPackts.get()
        
        # Capture packets and get entropy result
        self.tc.getEntropyResult()
    
    # Quit option event-handler
    # Displays a messagebox giving the user the option
    # to end the program or not
    def exitProgram(self, event=None):
        if tkMessageBox.askokcancel("Quit?", "Really quit?"):
            root.destroy()    
    
    # Stop the active thread when the 'Cancel' button is
    # clicked
    # ***** This method does not work as intended **
    # ***** More work is needed to fix this ********
    def cancelButtonEvent(self, event):
        self.tc.killThread()
        
    # Allow a user to open a file of previous entropy
    # results and view them in the program
    # ******Not fully operational  *********************
    # ******More work needed to finish this feature ****
    def openFile(self):
        filenameforReading = askopenfilename()
        dataManager = EntropyDataManager(filenameforReading)
        newText = dataManager.openFile()
        # clear any current text and place loaded text
        self.textArea.delete(1.0, 'end')
        self.textArea.insert(1.0, newText)
    
    # Save the entropy results displayed to a text file
    # ****Works but the text in the file is not formated***
    # **** in a reader-friendly way ****
    # **** More work needed to polish this feature ****
    def saveFile(self):
        filenameforWriting = asksaveasfilename()
        dataManager = EntropyDataManager(filenameforWriting)
        # end-1c prevents final newline character from being saved to file
        saveText = self.textArea.get(1.0, 'end-1c')
        dataManager.saveFile(saveText)
    
    # Display entropy result to user
    # Get the results that are in the queue and place them
    # in the textArea
    def processIncoming(self):
        while self.queue.qsize( ):
            try:
                msg = self.queue.get(0)
                
                # Insert results in the queue in the textarea
                self.textArea.insert(Tkinter.END, repr(msg) + "\n")
                print msg
            except Queue.Empty:
                # Do nothing
                pass


# Represents a thread client that creates a worker thread that
# will work asynchronously with the GUI thread.
# This thread will share the results of it's work with the GUI
# via a shared queue. This thread periodically yeilds control to
# the GUI so that it may check the contents of the queue.
class ThreadedClient:
    def __init__(self, master):

        self.master = master # TK inter root
        self.pc = PacketCapture()
        
        # Boolean to start/stop recieving entropy result
        self.inEntropyMode = False        

        # Create the queue
        self.queue = Queue.Queue()

        # Set up the GUI part. Share queue contents with the GUI
        self.gui = EntropyGUI(master, self.queue, self.endApplication, self)

        # Set up the thread to do asynchronous I/O
        self.running = 1
        
        # Create and start the thread
        self.thread1 = threading.Thread(target=self.workerThread1)
        self.thread1.start()

        # Start the periodic call in the GUI to check if the queue contains
        # anything
        self.periodicCall()        
    
    # Sets the boolean variable that puts the thread in
    # packet capture entropy mode or not
    def getEntropyResult(self):
        self.inEntropyMode = True

        
    # Kills thread when cancel button clicked in GUI
    # There's no way of killing thread from outside
    # Must create extended thread class that has the ability to
    # be terminated from outside the thread
    def killThread(self):
        pass
    
    # Allows the GUI to check every 200 ms if there is something
    # new in the queue   
    def periodicCall(self):

        self.gui.processIncoming( )
        if not self.running:
            # This is the brutal stop of the system. You may want to do
            # some cleanup before actually shutting it down.
            self.master.destroy()
        self.master.after(200, self.periodicCall)

    # Captures packets and gets an entropy result
    # The results are placed in a queue
    # Thread yeilds control to GUI by sleeping periodically
    def workerThread1(self):

        while self.running:
            eResult = ""
            if self.inEntropyMode:
                ip = socket.gethostbyname(self.gui.host)
                
                # Capture packets and get entropy result
                eResult = self.pc.capturePackets(ip, int(self.gui.numPackets))
            
            # yield control to GUI. May need to fine tune this pause
            time.sleep(rand.random(  ) * 1.5)
            
            # If we have a result put it in the queue
            # and signal to get out of entropy mode (stop getting results)
            if not eResult == "":
                self.queue.put("Entropy Result on " + self.gui.numPackets + " Packets: " + str(eResult))
                self.inEntropyMode = False

    def endApplication(self):
        self.running = 0
        self.inEntropyMode = False

rand = random.Random(  )
root = Tkinter.Tk(  )

client = ThreadedClient(root)
root.mainloop(  )
