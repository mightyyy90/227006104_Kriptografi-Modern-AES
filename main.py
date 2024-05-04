import tkinter as tk
from tkinter import messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

plaintext_entry = None
ciphertext_entry = None
decrypted_text_entry = None
output_format = None
key = None

def encrypt_AES(data):
    global key
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def decrypt_AES(data):
    global key
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)
    return pt.decode('utf-8', 'ignore')

def encrypt_text():
    global plaintext_entry, ciphertext_entry, output_format, key
    plaintext = plaintext_entry.get().strip()
    if plaintext:
        key = get_random_bytes(16)
        encrypted_data = encrypt_AES(plaintext)
        if output_format.get() == "Base64":
            ciphertext_entry.delete('1.0', tk.END)
            ciphertext_entry.insert('1.0', base64.b64encode(encrypted_data).decode())
        elif output_format.get() == "Hex":
            ciphertext_entry.delete('1.0', tk.END)
            ciphertext_entry.insert('1.0', encrypted_data.hex())
    else:
        messagebox.showerror("Error", "Plaintext cannot be empty")

def decrypt_text():
    global ciphertext_entry, decrypted_text_entry, key
    data = ciphertext_entry.get('1.0', tk.END).strip()
    if data:
        if output_format.get() == "Base64":
            data = base64.b64decode(data)
        else:
            data = bytes.fromhex(data)
        decrypted_data = decrypt_AES(data)
        decrypted_text_entry.delete(0, tk.END)
        decrypted_text_entry.insert(0, decrypted_data)
    else:
        messagebox.showerror("Error", "Ciphertext cannot be empty")

def clear_all():
    global plaintext_entry, ciphertext_entry, decrypted_text_entry
    plaintext_entry.delete(0, tk.END)
    ciphertext_entry.delete('1.0', tk.END)
    decrypted_text_entry.delete(0, tk.END)

def main():
    global plaintext_entry, ciphertext_entry, decrypted_text_entry, output_format

    root = tk.Tk()
    root.title("AES Encryption/Decryption")

    plaintext_label = tk.Label(root, text="Plaintext:")
    plaintext_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
    plaintext_entry = tk.Entry(root, width=40)
    plaintext_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5)

    ciphertext_label = tk.Label(root, text="Ciphertext:")
    ciphertext_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
    ciphertext_entry = scrolledtext.ScrolledText(root, width=40, height=5, wrap=tk.WORD)
    ciphertext_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

    decrypted_text_label = tk.Label(root, text="Decrypted Text:")
    decrypted_text_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
    decrypted_text_entry = tk.Entry(root, width=40)
    decrypted_text_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)

    output_format_label = tk.Label(root, text="Output Format:")
    output_format_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")

    output_format = tk.StringVar()
    output_format.set("Base64")
    base64_radio = tk.Radiobutton(root, text="Base64", variable=output_format, value="Base64")
    base64_radio.grid(row=3, column=1, padx=5, pady=5)
    hex_radio = tk.Radiobutton(root, text="Hex", variable=output_format, value="Hex")
    hex_radio.grid(row=3, column=2, padx=5, pady=5)

    encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text)
    encrypt_button.grid(row=4, column=1, padx=5, pady=5)

    decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text)
    decrypt_button.grid(row=4, column=2, padx=5, pady=5)

    clear_button = tk.Button(root, text="Clear All", command=clear_all)
    clear_button.grid(row=5, column=1, columnspan=2, padx=5, pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
