import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
from tkinter import filedialog
from tkinterdnd2 import DND_FILES, TkinterDnD 

def pad(plaintext):
    """Pad the plaintext to make it 16 bytes long."""
    padding_length = 16 - (len(plaintext) % 16)
    return plaintext + bytes([padding_length] * padding_length)

def unpad(plaintext):
    """Remove the padding from the plaintext."""
    padding_length = plaintext[-1]
    return plaintext[:-padding_length]

# ... (keep all the existing AES-related functions and classes)
sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

# Inverse S-box
inv_sbox = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

# Rcon (Round Constant) table
Rcon = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
]

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = sbox[state[i][j]]
    return state

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_sbox[state[i][j]]
    return state

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state

def inv_shift_rows(state):
    state[1] = state[1][3:] + state[1][:3]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][1:] + state[3][:1]
    return state

def mix_columns(state):
    
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        col = [col[0] ^ col[1] ^ col[2], col[1] ^ col[2] ^ col[3], 
               col[2] ^ col[3] ^ col[0], col[3] ^ col[0] ^ col[1]]
        for j in range(4):
            state[j][i] = col[j]
    return state

def inv_mix_columns(state):
    
    return mix_columns(mix_columns(mix_columns(state)))

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def key_expansion(key):
    
    key_words = [key[i:i+4] for i in range(0, len(key), 4)]
    for i in range(4, 44):
        temp = key_words[i-1]
        if i % 4 == 0:
            temp = [sbox[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= Rcon[i//4]
        key_words.append([a ^ b for a, b in zip(key_words[i-4], temp)])
    return [word for words in key_words for word in words]

class AES:
    def __init__(self, key):
        self.round_keys = key_expansion(key)

    def encrypt(self, plaintext):
        state = [[plaintext[i+j*4] for j in range(4)] for i in range(4)]
        state = add_round_key(state, [self.round_keys[i:i+4] for i in range(0, 16, 4)])
        
        for round in range(1, 10):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, [self.round_keys[round*16+i:round*16+i+4] for i in range(0, 16, 4)])
        
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, [self.round_keys[160+i:160+i+4] for i in range(0, 16, 4)])
        
        return bytes(state[i][j] for j in range(4) for i in range(4))

    def decrypt(self, ciphertext):
        state = [[ciphertext[i+j*4] for j in range(4)] for i in range(4)]
        state = add_round_key(state, [self.round_keys[160+i:160+i+4] for i in range(0, 16, 4)])
        
        for round in range(9, 0, -1):
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state)
            state = add_round_key(state, [self.round_keys[round*16+i:round*16+i+4] for i in range(0, 16, 4)])
            state = inv_mix_columns(state)
        
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, [self.round_keys[i:i+4] for i in range(0, 16, 4)])
        
        return bytes(state[i][j] for j in range(4) for i in range(4))

    @staticmethod
    def generate_random_key():
        return os.urandom(16)

class AESApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()

        self.title("AES Encryption/Decryption")
        self.geometry("700x600")
        self.configure(bg="#2b2b2b")

        self.style = ttk.Style(self)
        self.style.theme_create("darktheme", parent="alt", settings={
            "TNotebook": {"configure": {"background": "#2b2b2b", "tabmargins": [2, 5, 2, 0]}},
            "TNotebook.Tab": {
                "configure": {"padding": [10, 5], "background": "#3c3f41"},
                "map": {"background": [("selected", "#4eb25b")],
                        "expand": [("selected", [1, 1, 1, 0])]},
            },
            "TFrame": {"configure": {"background": "#2b2b2b"}},
            "TButton": {"configure": {"padding": [10, 5], "background": "#4eb25b", "foreground": "white", "borderwidth": "1.2rem"}},
            "TLabel": {"configure": {"background": "#2b2b2b", "foreground": "white"}},
            "TEntry": {"configure": {"insertbackground": "white"}},
        })
        self.style.theme_use("darktheme")

        notebook = ttk.Notebook(self)
        notebook.pack(pady=20, padx=20, expand=True, fill="both")

        encryption_tab = ttk.Frame(notebook)
        decryption_tab = ttk.Frame(notebook)
        notebook.add(encryption_tab, text="Encryption")
        notebook.add(decryption_tab, text="Decryption")

        # Encryption Tab
        self.create_encryption_tab(encryption_tab)

        # Decryption Tab
        self.create_decryption_tab(decryption_tab)

    def create_encryption_tab(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ttk.Label(frame, text="Select file to encrypt:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.encryption_file_path = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=self.encryption_file_path, width=40)
        entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        ttk.Button(frame, text="Browse", command=self.browse_encryption_file).grid(row=0, column=2, padx=10, pady=10)

        ttk.Label(frame, text="Key").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.key_entry = ttk.Entry(frame, width=40)
        self.key_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        generate_key_button = ttk.Button(frame, text="Generate Key", command=self.generate_key)
        generate_key_button.grid(row=2, column=1, padx=10, pady=10)

        encrypt_button = ttk.Button(frame, text="Encrypt", command=self.encrypt_file)
        encrypt_button.grid(row=3, column=1, padx=10, pady=10)

        # Drop zone
        drop_frame = ttk.Frame(frame, relief="groove", borderwidth=2)
        drop_frame.grid(row=4, column=0, columnspan=3, padx=10, pady=20, sticky="nsew")
        drop_label = ttk.Label(drop_frame, text="Drag and drop file here to encrypt automatically")
        drop_label.pack(expand=True, fill="both", padx=20, pady=20)

        drop_frame.drop_target_register(DND_FILES)
        drop_frame.dnd_bind('<<Drop>>', self.drop_file_encrypt)

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)

    def create_decryption_tab(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ttk.Label(frame, text="Select file to decrypt:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.decryption_file_path = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=self.decryption_file_path, width=40)
        entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        ttk.Button(frame, text="Browse", command=self.browse_decryption_file).grid(row=0, column=2, padx=10, pady=10)

        ttk.Label(frame, text="Key").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.decryption_key_entry = ttk.Entry(frame, width=40)
        self.decryption_key_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        decrypt_button = ttk.Button(frame, text="Decrypt", command=self.decrypt_file)
        decrypt_button.grid(row=2, column=1, padx=10, pady=10)

        # Drop zone
        drop_frame = ttk.Frame(frame, relief="groove", borderwidth=2)
        drop_frame.grid(row=3, column=0, columnspan=3, padx=10, pady=20, sticky="nsew")
        drop_label = ttk.Label(drop_frame, text="Drag and drop file here to decrypt")
        drop_label.pack(expand=True, fill="both", padx=20, pady=20)

        drop_frame.drop_target_register(DND_FILES)
        drop_frame.dnd_bind('<<Drop>>', self.drop_file_decrypt)

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)

    def drop_file_encrypt(self, event):
        file_path = event.data
        if file_path.startswith("{") and file_path.endswith("}"):
            file_path = file_path[1:-1]
        self.encryption_file_path.set(file_path)
        self.generate_key()
        self.encrypt_file(auto=True)

    def drop_file_decrypt(self, event):
        file_path = event.data
        if file_path.startswith("{") and file_path.endswith("}"):
            file_path = file_path[1:-1]
        self.decryption_file_path.set(file_path)

    def generate_key(self):
        key = AES.generate_random_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.hex())

    def browse_encryption_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.encryption_file_path.set(filename)

    def browse_decryption_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.decryption_file_path.set(filename)

    def encrypt_file(self, auto=False):
        input_file = self.encryption_file_path.get()
        key_hex = self.key_entry.get().strip()

        if not input_file:
            messagebox.showerror("Error", "Please select an input file.")
            return

        if not key_hex:
            if not auto:
                messagebox.showerror("Error", "Please enter a key or generate one.")
                return
            else:
                self.generate_key()
                key_hex = self.key_entry.get().strip()

        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 16:
                messagebox.showerror("Error", "Key must be 16 bytes (32 hex characters).")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid key format. Please enter a valid hex string.")
            return

        # Generate output filename
        base_name = os.path.basename(input_file)
        name, ext = os.path.splitext(base_name)
        output_file = os.path.join(os.path.dirname(input_file), f"{name}_encrypted{ext}.enc")

        aes = AES(key)

        try:
            with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                # Save the original file extension
                _, file_extension = os.path.splitext(input_file)
                f_out.write(len(file_extension).to_bytes(1, byteorder='big'))
                f_out.write(file_extension.encode())

                plaintext = f_in.read()
                padded_plaintext = pad(plaintext)
                for i in range(0, len(padded_plaintext), 16):
                    chunk = padded_plaintext[i:i+16]
                    encrypted_chunk = aes.encrypt(chunk)
                    f_out.write(encrypted_chunk)

            messagebox.showinfo("Success", f"File encrypted and saved as {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    def decrypt_file(self):
        input_file = self.decryption_file_path.get()
        key_hex = self.decryption_key_entry.get().strip()

        if not input_file:
            messagebox.showerror("Error", "Please select an input file.")
            return

        if not key_hex:
            messagebox.showerror("Error", "Please enter a key.")
            return

        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 16:
                messagebox.showerror("Error", "Key must be 16 bytes (32 hex characters).")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid key format. Please enter a valid hex string.")
            return

        aes = AES(key)

        try:
            with open(input_file, 'rb') as f_in:
                # Read the original file extension
                extension_length = int.from_bytes(f_in.read(1), byteorder='big')
                original_extension = f_in.read(extension_length).decode()

                ciphertext = f_in.read()
                decrypted_data = b''
                for i in range(0, len(ciphertext), 16):
                    chunk = ciphertext[i:i+16]
                    decrypted_chunk = aes.decrypt(chunk)
                    decrypted_data += decrypted_chunk
                unpadded_data = unpad(decrypted_data)

            # Use the original file extension for the output file
            output_file = filedialog.asksaveasfilename(defaultextension=original_extension)
            if not output_file:
                return

            with open(output_file, 'wb') as f_out:
                f_out.write(unpadded_data)

            messagebox.showinfo("Success", f"File decrypted and saved as {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    app = AESApp()
    app.mainloop()
