# This is a sample Python script.

# Press Shift+F6 to execute it or replace it with your code.
"""
import phoneScan
import FileScan
import sys
phoneScan.get_phone_number()
FileScan.get_file_scan()

"""
# Below are code for the GUI
import sys
import ctypes
import tkinter as tk
from tkinter import filedialog
from tkinter import *
import MalShare
from MalShare import get_malshare_info

#Makes GUI less blurry
#if 'win' in sys.platform:
#    ctypes.windll.shcore.SetProcessDpiAwareness(1)

main = Tk() #Tkinter window

#Window styles
main.geometry("600x600") #window size
main.title("Global Search") #Title of window 

#sets logo at top bar
logo = PhotoImage(file='logo.png')
main.iconphoto(True,logo)
main.config(background="#4A4459") #background color


#Text for instructions
home = Label(main,
             text="Pick a service:", 
             font=('Courier New',12), 
             fg="white", 
             bg="#4A4459", 
             padx=10,
             pady=10)
home.pack()

#Functions for each API Windows
"""
Create functions for every buttons
"""
def create_window(button):
    title_text = button.cget("text")
    
    new_window = Tk()
    new_window.title(title_text)
    new_window.geometry("400x400")
    
    main.destroy()  #closes main window

#MalShare window function
def malShare_window():
    new_window = tk.Toplevel(main)
    new_window.title("MalShare")
    new_window.geometry("600x600")
    new_window.config(background="#4A4459")

    def compute_sha256(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    #Function to open file 
    def openFile():
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        print("Selected:", filepath)
        hash_value = compute_sha256(filepath)
        print("File hash:", hash_value)
        # Correct call
        get_malshare_info(file_hash=hash_value, save_path="malshare_result.json")
    #MalShare button
    tk.Button(new_window, 
              text="Select a File", 
              command=openFile,
              font=('Courier New', 12), 
              bg="#00C3EB", 
              fg="black", 
              activebackground='#FF0000', 
              activeforeground='white',
              width=20).pack()
    main.withdrawl()  #closes main window

#Main window buttons
malShare = Button(main, 
                  text='Malshare', 
                  command=malShare_window, 
                  font=('Courier New', 12), 
                  bg="#00C3EB", 
                  fg="black", 
                  activebackground='#FF0000', 
                  activeforeground='white',
                  width=20).pack()

#Move this function at the top
#URLScan Window Function
def urlScan_window():
    new_window = tk.Toplevel(main)
    new_window.title("URLScan")
    new_window.geometry("400x400")
    new_window.config(background="#4A4459")
    main.withdrawl()  #closes main window

urlScan = Button(main,text='URLScan')
urlScan.config(command=lambda:create_window(urlScan),
              font=('Courier New', 12),  
              bg="#00C3EB", 
              fg="black", 
              activebackground='#FF0000', 
              activeforeground='white',
              width=20)
urlScan.pack(pady=20)

webOfTrust = Button(main,text='WebofTrust')
webOfTrust.config(command=lambda:create_window(webOfTrust),
              font=('Courier New', 12), 
              bg="#00C3EB", 
              fg="black", 
              activebackground='#FF0000', 
              activeforeground='white',
              width=20)
webOfTrust.pack(pady=20)

veriPhone = Button(main,text='Veriphone')
veriPhone.config(command=lambda:create_window(veriPhone),
              font=('Courier New', 12), 
              bg="#00C3EB", 
              fg="black", 
              activebackground='#FF0000', 
              activeforeground='white',
              width=20)
veriPhone.pack(pady=20)

virusTotal = Button(main,text='VirusTotal')
virusTotal.config(command=lambda:create_window(virusTotal),
              font=('Courier New', 12), 
              bg="#00C3EB", 
              fg="black", 
              activebackground='#FF0000', 
              activeforeground='white',
              width=20)
virusTotal.pack(pady=20)

End = Button(main,text='Exit')
End.config(command=main.quit,
           font=('Courier New', 12), 
           bg="#00C3EB", 
           fg="black", 
           activebackground='#FF0000', 
           activeforeground='white',
           width=20)
End.pack(pady=20)
#ends application

main.mainloop()