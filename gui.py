import tkinter as tk
from tkinter import ttk, messagebox
import os
from custom_aes import AES

class AES:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        
        return plaintext  

    def decrypt(self, ciphertext):
       
        return ciphertext  
def pad(text):
    """PKCS7 padding"""
    padding_length = 16 - (len(text) % 16)
    return text + bytes([padding_length] * padding_length)

def unpad(text):
    """Remove PKCS7 padding"""
    padding_length = text[-1]
    return text[:-padding_length]

def generate_key():
    """Generate a random 16-byte key"""
    return os.urandom(16)

class AESApp:
    def __init__(self, master):
        self.master = master
        master.title("AES Encryption/Decryption")
        master.geometry("600x600")
        master.resizable(False, False)

        style = ttk.Style()
        style.theme_use('clam')

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.encrypt_frame = ttk.Frame(self.notebook)
        self.decrypt_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.encrypt_frame, text="Encrypt")
        self.notebook.add(self.decrypt_frame, text="Decrypt")

        self.setup_encrypt_frame()
        self.setup_decrypt_frame()

    def setup_encrypt_frame(self):
        ttk.Label(self.encrypt_frame, text="Plaintext:").pack(pady=(10, 0))
        self.plaintext_entry = tk.Text(self.encrypt_frame, width=50, height=5)
        self.plaintext_entry.pack(pady=(0, 10))

        ttk.Label(self.encrypt_frame, text="Key (32 hexadecimal characters):").pack()
        self.encrypt_key_entry = ttk.Entry(self.encrypt_frame, width=50)
        self.encrypt_key_entry.pack(pady=(0, 5))

        key_button_frame = ttk.Frame(self.encrypt_frame)
        key_button_frame.pack(pady=(0, 10))
        ttk.Button(key_button_frame, text="Generate Key", command=lambda: self.generate_key(self.encrypt_key_entry)).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_button_frame, text="Clear Key", command=lambda: self.clear_key(self.encrypt_key_entry)).pack(side=tk.LEFT, padx=5)

        ttk.Button(self.encrypt_frame, text="Encrypt", command=self.encrypt).pack(pady=10)

        ttk.Label(self.encrypt_frame, text="Ciphertext (hex format):").pack()
        self.ciphertext_result = tk.Text(self.encrypt_frame, width=50, height=5, state='disabled')
        self.ciphertext_result.pack(pady=(0, 10))

    def setup_decrypt_frame(self):
        ttk.Label(self.decrypt_frame, text="Ciphertext (hex format):").pack(pady=(10, 0))
        self.ciphertext_entry = tk.Text(self.decrypt_frame, width=50, height=5)
        self.ciphertext_entry.pack(pady=(0, 10))

        ttk.Label(self.decrypt_frame, text="Key (32 hexadecimal characters):").pack()
        self.decrypt_key_entry = ttk.Entry(self.decrypt_frame, width=50)
        self.decrypt_key_entry.pack(pady=(0, 5))

        key_button_frame = ttk.Frame(self.decrypt_frame)
        key_button_frame.pack(pady=(0, 10))
        ttk.Button(key_button_frame, text="Generate Key", command=lambda: self.generate_key(self.decrypt_key_entry)).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_button_frame, text="Clear Key", command=lambda: self.clear_key(self.decrypt_key_entry)).pack(side=tk.LEFT, padx=5)

        ttk.Button(self.decrypt_frame, text="Decrypt", command=self.decrypt).pack(pady=10)

        ttk.Label(self.decrypt_frame, text="Plaintext:").pack()
        self.plaintext_result = tk.Text(self.decrypt_frame, width=50, height=5, state='disabled')
        self.plaintext_result.pack(pady=(0, 10))

    def generate_key(self, entry_widget):
        key = generate_key()
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, key.hex())

    def clear_key(self, entry_widget):
        entry_widget.delete(0, tk.END)

    def encrypt(self):
        plaintext = self.plaintext_entry.get("1.0", tk.END).strip()
        key = self.encrypt_key_entry.get().strip()

        try:
            if len(key) != 32:  
                raise ValueError("Key must be exactly 32 hexadecimal characters")

            plaintext_bytes = plaintext.encode('utf-8')
            padded_plaintext = pad(plaintext_bytes)
            key_bytes = bytes.fromhex(key)

            aes = AES(key_bytes)
            ciphertext = bytes(aes.encrypt(padded_plaintext))

            self.ciphertext_result.config(state='normal')
            self.ciphertext_result.delete("1.0", tk.END)
            self.ciphertext_result.insert(tk.END, ciphertext.hex())
            self.ciphertext_result.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        ciphertext = self.ciphertext_entry.get("1.0", tk.END).strip()
        key = self.decrypt_key_entry.get().strip()
        try:
            if len(key) != 32:
                raise ValueError("Key must be exactly 32 hexadecimal characters")
            ciphertext_bytes = bytes.fromhex(ciphertext)
            key_bytes = bytes.fromhex(key)
            
            if len(ciphertext_bytes) % 16 != 0:
                raise ValueError("Ciphertext length must be a multiple of 16 bytes")
            aes = AES(key_bytes)
            plaintext = bytes(aes.decrypt(ciphertext_bytes))
            unpadded_plaintext = unpad(plaintext)
            decoded_plaintext = unpadded_plaintext.decode('utf-8')
            self.plaintext_result.config(state='normal')
            self.plaintext_result.delete("1.0", tk.END)
            self.plaintext_result.insert(tk.END, decoded_plaintext)
            self.plaintext_result.config(state='disabled')
        except UnicodeDecodeError:
            messagebox.showerror("Error", "Unable to decrypt. The key may be incorrect.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()
