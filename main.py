# This is a sample Python script.

# Press Shift+F6 to execute it or replace it with your code.
"""
import phoneScan
import sys
phoneScan.get_phone_number()

"""
# Below are code for the GUI
import sys
import ctypes
from tkinter import *

#Makes GUI less blurry
if 'win' in sys.platform:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)

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


#Main window buttons
malShare = Button(main,text='Malshare')
malShare.config(command=lambda:create_window(malShare),
              font=('Courier New', 12), 
              bg="#00C3EB", 
              fg="black", 
              activebackground='#FF0000', 
              activeforeground='white',
              width=20)
malShare.pack(pady=20)

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