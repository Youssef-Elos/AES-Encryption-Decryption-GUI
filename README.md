# AES-Encryption-Decryption-GUI
AES Encryption/Decryption with Key Verification and a GUI

This project implements AES encryption and decryption with a graphical user interface (GUI) using Python's `tkinter` library. It also includes key verification using a SHA-256 hash to ensure that only the correct key can decrypt the encrypted text.

## Features

- AES encryption and decryption
- Key verification using SHA-256 hash
- Simple and intuitive GUI

## Requirements

- Python 3.x
- `tkinter` library (usually included with Python)
- `hashlib` library (included with Python)

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/aes-encryption.git
    cd aes-encryption
    ```

2. Ensure you have Python 3.x installed. You can download it from [python.org](https://www.python.org/).

## Usage

1. Run the application:
    ```sh
    python your_script_name.py
    ```

2. The GUI will open. You can enter the text you want to encrypt or decrypt and the key.

3. Click the "Encrypt" button to encrypt the text or the "Decrypt" button to decrypt the text.

## Key Verification

The application uses a SHA-256 hash to verify the key. The correct key's hash is stored securely within the application. When a user provides a key, its hash is compared to the stored hash to verify its correctness.

### Example Code Snippet

Here's a snippet showing how key verification is implemented:

```python
import hashlib
import tkinter as tk
from tkinter import messagebox

class YourClass:
    # Other parts of your class

    def generate_key_hash(self, key):
        """Generate a SHA-256 hash of the given key."""
        return hashlib.sha256(key.encode()).hexdigest()

    def verify_key(self, user_key):
        """Verify the user-provided key against the stored hash."""
        # Example stored hash of the correct key (you should generate this securely and store it)
        stored_hash = "your_stored_hash_here"
        user_key_hash = self.generate_key_hash(user_key)
        return user_key_hash == stored_hash

    def encrypt(self):
        text = self.text_entry.get().strip()
        key = self.key_entry.get().strip()

        if not self.verify_key(key):
            messagebox.showerror("Error", "Incorrect key")
            return

        # Your existing encryption logic

    def decrypt(self):
        text = self.text_entry.get().strip()
        key = self.key_entry.get().strip()

        if not self.verify_key(key):
            messagebox.showerror("Error", "Incorrect key")
            return

        # Your existing decryption logic
