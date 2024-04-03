
#IMAGE ENCRYPTION
#AES CBC
#By Polakorn Anatapakorn 6587093

from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from os import listdir
from os.path import isfile, join
from base64 import b64decode, b64encode

from tkinter import*
from tkinter import ttk
import tkinter as tk
from tkinter.filedialog import *
import tkinter.messagebox
from PIL import Image,ImageTk
import hashlib
import os
from Crypto.Random import get_random_bytes

def encrypt():
    try:
        global file_path_e
        key = get_random_bytes(AES.block_size)

        #LOAD THE IMAGE
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)

        file_name = join(file_path_e , filename)
        with open(file_name, 'rb') as f:
            plaintext = f.read()
            iv = get_random_bytes(AES.block_size)
            print(iv)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = key + iv + cipher.encrypt(pad(plaintext, AES.block_size))
            #Create HashCode
            sha256_hash = hashlib.sha256(ciphertext).digest()
            hashcode = sha256_hash
            print(hashcode)
            ciphertext = hashcode + ciphertext
            ciphertext = b64encode(ciphertext)

        with open(file_name + '.enc', 'wb') as f:
            f.write(ciphertext)

        tkinter.messagebox.showinfo("Encryption Alert","Encryption ended successfully. File stored as: encrypted.enc")

    except Exception as e:
        tkinter.messagebox.showinfo("Encryption Alert","Encryption Fail")
        print(f"Error encrypting {filename}: {e}")

def decrypt():
    try:
        global file_path_e
        
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)

        file_name = join(file_path_e , filename)
        with open(file_name, 'rb') as f:
            ciphertext = b64decode(f.read())
            hash_size = 32
            hashcode = ciphertext[: hash_size]
            key = ciphertext[hash_size: AES.block_size+hash_size]
            iv = ciphertext[AES.block_size+hash_size:AES.block_size+ hash_size +16]
            ciphertext_body = ciphertext[AES.block_size+hash_size+16: ]  # Exclude hashcode for decryption
        
            # Calculate SHA-256 hash of ciphertext body
            sha256_hash = hashlib.sha256(key + iv + ciphertext_body).digest()

            # Compare calculated hashcode with the one appended to ciphertext
            if sha256_hash != hashcode:
                tkinter.messagebox.showinfo("Decryption Alert", "Hashcode mismatch! File might be tampered.")
                return

            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext_body), AES.block_size)

        with open(file_name[:-4], 'wb') as f:
            f.write(plaintext)

        tkinter.messagebox.showinfo("Decryption Alert", "Decryption ended successfully")

        # Show decrypted image
        decrypted_image_path = file_name[:-4]
        decrypted_image = Image.open(decrypted_image_path)
        decrypted_image.show()
        os.remove(decrypted_image_path)

    except Exception as e:
        tkinter.messagebox.showinfo("Decryption Alert", "Decryption Fail")
        print(f"Error browsing {filename}: {e}")



# GUI STUFF
top=tk.Tk()
top.geometry("500x150")
top.resizable(0,0)
top.title("ImageEncryption")

title="Image Encryption Using AES"
msgtitle=Message(top,text=title)
msgtitle.config(font=('helvetica',17,'bold'),width=300)
msgtitle.pack()

sp="---------------------------------------------------------------------"
sp_title=Message(top,text=sp)
sp_title.config(font=('arial',12),width=650)
sp_title.pack()


# passlabel = Label(top, text="Enter Encryption/Decryption Key:")
# passlabel.pack()
# passg = Entry(top, show="*", width=20)
# passg.config(highlightthickness=1,highlightbackground="blue")
# passg.pack()

encrypt=Button(top,text="Save Image",width=28,height=3,command=encrypt)
encrypt.pack(side=LEFT)
decrypt=Button(top,text="Open",width=28,height=3,command=decrypt)
decrypt.pack(side=RIGHT)

top.mainloop()
