import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import secrets

FAILED_ATTEMPTS_LIMIT = 1
failed_attempts = {}

def generate_key(password: str, salt: bytes) -> bytes:
    """Derives a key from the password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str, destination: str):
    """Encrypts the file and saves it in the destination folder."""
    try:
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        # Generate salt and key
        salt = secrets.token_bytes(16)
        key = generate_key(password, salt)

        # Encrypt data
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Save encrypted file
        filename = os.path.basename(file_path) + ".enc"
        encrypted_file_path = os.path.join(destination, filename)
        with open(encrypted_file_path, 'wb') as enc_file:
            enc_file.write(salt + iv + ciphertext)

        # Delete the original file
        os.remove(file_path)
        messagebox.showinfo("Success", f"File encrypted and saved to {encrypted_file_path}. Original file deleted.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")


def decrypt_file(file_path: str, password: str):
    """Decrypts the file if the password is correct."""
    global failed_attempts

    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]

        key = generate_key(password, salt)

        # Decrypt data
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Only prompt for save location after successful decryption
        decrypted_file_path = filedialog.asksaveasfilename(title="Save Decrypted File")
        if decrypted_file_path:
            with open(decrypted_file_path, 'wb') as dec_file:
                dec_file.write(plaintext)
            messagebox.showinfo("Success", f"File decrypted and saved to {decrypted_file_path}")

    except Exception:
        # Increment failed attempts
        failed_attempts[file_path] = failed_attempts.get(file_path, 0) + 1
        if failed_attempts[file_path] >= FAILED_ATTEMPTS_LIMIT:
            shred_file(file_path)
            messagebox.showwarning("File Deleted", "File deleted after 5 failed decryption attempts.")
        else:
            messagebox.showerror("Error", "Decryption failed. Incorrect password.")


def shred_file(file_path: str):
    """Securely deletes the file using shredding."""
    try:
        with open(file_path, "ba+") as file:
            length = file.tell()
        with open(file_path, "br+") as file:
            file.write(secrets.token_bytes(length))
        os.remove(file_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete the file securely: {e}")

def browse_file(entry_field):
    """Browse for a file."""
    file_path = filedialog.askopenfilename()
    entry_field.delete(0, tk.END)
    entry_field.insert(0, file_path)

def browse_folder(entry_field):
    """Browse for a folder."""
    folder_path = filedialog.askdirectory()
    entry_field.delete(0, tk.END)
    entry_field.insert(0, folder_path)

def create_encrypt_ui():
    """Create the UI for encryption."""
    window = tk.Toplevel(root)
    window.title("Encrypt File")

    tk.Label(window, text="Choose File").grid(row=0, column=0, padx=10, pady=5)
    file_entry = tk.Entry(window, width=40)
    file_entry.grid(row=0, column=1, padx=10, pady=5)
    tk.Button(window, text="Browse", command=lambda: browse_file(file_entry)).grid(row=0, column=2, padx=10, pady=5)

    tk.Label(window, text="Enter Password").grid(row=1, column=0, padx=10, pady=5)
    password_entry = tk.Entry(window, width=40, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=5)

    tk.Label(window, text="Save To").grid(row=2, column=0, padx=10, pady=5)
    destination_entry = tk.Entry(window, width=40)
    destination_entry.grid(row=2, column=1, padx=10, pady=5)
    tk.Button(window, text="Browse", command=lambda: browse_folder(destination_entry)).grid(row=2, column=2, padx=10, pady=5)

    tk.Button(window, text="Encrypt", command=lambda: encrypt_file(
        file_entry.get(), password_entry.get(), destination_entry.get())).grid(row=3, column=1, pady=10)

def create_decrypt_ui():
    """Create the UI for decryption."""
    window = tk.Toplevel(root)
    window.title("Decrypt File")

    tk.Label(window, text="Choose Encrypted File").grid(row=0, column=0, padx=10, pady=5)
    file_entry = tk.Entry(window, width=40)
    file_entry.grid(row=0, column=1, padx=10, pady=5)
    tk.Button(window, text="Browse", command=lambda: browse_file(file_entry)).grid(row=0, column=2, padx=10, pady=5)

    tk.Label(window, text="Enter Password").grid(row=1, column=0, padx=10, pady=5)
    password_entry = tk.Entry(window, width=40, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=5)

    tk.Button(window, text="Decrypt", command=lambda: decrypt_file(
        file_entry.get(), password_entry.get())).grid(row=2, column=1, pady=10)

# Main Window
root = tk.Tk()
root.title("File Sentinal")
root.geometry("400x300")

tk.Button(root, text="Encrypt File", command=create_encrypt_ui, width=20).pack(pady=10)
tk.Button(root, text="Decrypt File", command=create_decrypt_ui, width=20).pack(pady=10)

root.mainloop()
