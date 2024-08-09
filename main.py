from tkinter import *
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import hashlib
import base64

FONT = "Arial", 16, "bold"

# UI
window = Tk()
window.title("Secret Notes")
window.minsize(width=500, height=800)

# Pillow ile resmi yeniden boyutlandırma
original_image = Image.open("top secret.png")
resized_image = original_image.resize((200, 200))

# tkinter için yeniden boyutlandırılmış resmi dönüştürme işlemi
image = ImageTk.PhotoImage(resized_image)

# Label içinde resmi göster
image_label = Label(window, image=image)
image_label.pack()

title_label = Label(text="Enter your title")
title_label.config(bg="white", fg="black", font=FONT)
title_label.pack()

title_entry = Entry(width=50)
title_entry.pack()

secret_label = Label(text="Enter your secret")
secret_label.config(bg="white", fg="black", font=FONT)
secret_label.pack()

secret_text = Text(width=38, height=20)
secret_text.pack()

key_label = Label(text="Enter master key")
key_label.config(bg="white", fg="black", font=FONT)
key_label.pack()

key_entry = Entry(width=50)
key_entry.pack()


def generate_key(master_key):
    digest = hashlib.sha256(master_key.encode()).digest()
    return base64.urlsafe_b64encode(digest[:32])


def encrypt_secret(secret, master_key):
    key = generate_key(master_key)
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(secret.encode())
    return encrypted_text


def save_encrypted(title, encrypted_secret):
    with open(f"{title}.txt", "wb") as file:
        file.write(encrypted_secret)


def decrypt_secret(encrypted_secret, master_key):
    key = generate_key(master_key)
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_secret).decode()
    return decrypted_text


def save_and_encrypt():
    title = title_entry.get()
    secret = secret_text.get("1.0", END).strip()
    master_key = key_entry.get()

    encrypted_secret = encrypt_secret(secret, master_key)
    save_encrypted(title, encrypted_secret)
    print("Secret encrypted and saved!")


def decrypt():
    title = title_entry.get()
    master_key = key_entry.get()

    with open(f"{title}.txt", "rb") as file:
        encrypted_secret = file.read()

    decrypted_secret = decrypt_secret(encrypted_secret, master_key)

    secret_text.delete("1.0", END)
    secret_text.insert(END, decrypted_secret)


save_button = Button(text="Save & Encrypt", command=save_and_encrypt)
save_button.pack()

decrypt_button = Button(text="Decrypt", command=decrypt)
decrypt_button.pack()

window.mainloop()
