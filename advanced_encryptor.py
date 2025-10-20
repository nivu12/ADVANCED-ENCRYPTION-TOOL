import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import tempfile

# ---- Config ----
PBKDF2_ITERATIONS = 200_000
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
MAGIC = b'AEToolV1'

# ---- Encryption helper functions ----
def build_encrypted_blob(salt, nonce, tag, ciphertext):
    return b''.join([MAGIC, bytes([len(salt)]), salt,
                     bytes([len(nonce)]), nonce,
                     bytes([len(tag)]), tag,
                     ciphertext])

def parse_encrypted_blob(blob):
    if blob[:8] != MAGIC:
        raise ValueError("Not an AETool encrypted file")
    idx = 8
    slen = blob[idx]; idx+=1
    salt = blob[idx:idx+slen]; idx+=slen
    nlen = blob[idx]; idx+=1
    nonce = blob[idx:idx+nlen]; idx+=nlen
    tlen = blob[idx]; idx+=1
    tag = blob[idx:idx+tlen]; idx+=tlen
    ciphertext = blob[idx:]
    return salt, nonce, tag, ciphertext

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_LEN, count=PBKDF2_ITERATIONS)

def encrypt_bytes(plaintext: bytes, password: str):
    salt = get_random_bytes(SALT_LEN)
    key = derive_key_from_password(password, salt)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return build_encrypted_blob(salt, nonce, tag, ciphertext)

def decrypt_bytes(blob: bytes, password: str):
    salt, nonce, tag, ciphertext = parse_encrypted_blob(blob)
    key = derive_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("Decryption failed: wrong password or file corrupted")

def encrypt_file(in_path, out_path, password):
    with open(in_path, 'rb') as f:
        data = f.read()
    blob = encrypt_bytes(data, password)
    with open(out_path, 'wb') as f:
        f.write(blob)

def decrypt_file(in_path, out_path, password):
    with open(in_path, 'rb') as f:
        blob = f.read()
    plaintext = decrypt_bytes(blob, password)
    with open(out_path, 'wb') as f:
        f.write(plaintext)

# ---- Helper function to replace original with encrypted file ----
def encrypt_and_replace_original(in_path: str, password: str):
    if not os.path.isfile(in_path):
        raise FileNotFoundError("Input file not found")

    # Read original bytes
    with open(in_path, "rb") as f:
        original_bytes = f.read()

    # Create temp encrypted file
    dirpath = os.path.dirname(in_path) or "."
    fd_temp, tmp_enc_path = tempfile.mkstemp(prefix=os.path.basename(in_path) + ".", suffix=".enc.tmp", dir=dirpath)
    os.close(fd_temp)

    try:
        # Encrypt to temp file
        blob = encrypt_bytes(original_bytes, password)
        with open(tmp_enc_path, "wb") as tf:
            tf.write(blob)

        # Verify encryption
        with open(tmp_enc_path, "rb") as tf:
            blob_read = tf.read()
        decrypted_check = decrypt_bytes(blob_read, password)
        if decrypted_check != original_bytes:
            os.remove(tmp_enc_path)
            raise RuntimeError("Verification failed. Encryption aborted.")

        # Backup original
        backup_path = in_path + ".bak"
        if os.path.exists(backup_path):
            backup_path = backup_path + ".old"
        os.replace(in_path, backup_path)

        # Move encrypted temp to final .enc filename
        final_enc_path = in_path + ".enc"
        os.replace(tmp_enc_path, final_enc_path)

        # Remove backup
        try:
            os.remove(backup_path)
        except OSError:
            pass

        return final_enc_path

    except Exception:
        if os.path.exists(tmp_enc_path):
            try:
                os.remove(tmp_enc_path)
            except OSError:
                pass
        raise

# ---- GUI ----
class AdvancedEncryptor:
    def __init__(self, root):
        self.root = root
        root.title("Advanced Encryption Tool (AES-256-GCM)")
        root.geometry("560x280")
        root.minsize(560, 280)
        root.resizable(True, True)

        # ---- Load background image ----
        self.bg_image_orig = Image.open("ency.png")
        self.bg_photo = ImageTk.PhotoImage(self.bg_image_orig)

        # ---- Background Label ----
        self.bg_label = tk.Label(root, image=self.bg_photo)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        # ---- Variables ----
        self.file_var = tk.StringVar()
        self.pw_var = tk.StringVar()

        # ---- Widgets ----
        tk.Label(self.bg_label, text="Filename:", bg="#ffffff").place(x=30, y=30)
        tk.Entry(self.bg_label, textvariable=self.file_var, width=60).place(x=30, y=60)

        tk.Label(self.bg_label, text="Password:", bg="#ffffff").place(x=30, y=100)
        tk.Entry(self.bg_label, textvariable=self.pw_var, width=60, show="*").place(x=30, y=130)

        tk.Button(self.bg_label, text="Browse File", width=15, command=self.browse_file).place(x=30, y=160)
        tk.Button(self.bg_label, text="Encrypt", width=15, command=self.on_encrypt).place(x=200, y=160)
        tk.Button(self.bg_label, text="Decrypt", width=15, command=self.on_decrypt).place(x=370, y=160)

        self.status = tk.StringVar(value="Ready")
        tk.Label(self.bg_label, textvariable=self.status, bg="#ffffff").place(x=30, y=200)

        root.bind("<Configure>", self.resize_bg)

    # ---- Resize background ----
    def resize_bg(self, event):
        if event.width > 0 and event.height > 0:
            resized = self.bg_image_orig.resize((event.width, event.height))
            self.bg_photo_resized = ImageTk.PhotoImage(resized)
            self.bg_label.config(image=self.bg_photo_resized)

    # ---- Browse file ----
    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_var.set(path)

    # ---- Encrypt ----
    def on_encrypt(self):
        in_path = self.file_var.get().strip()
        pw = self.pw_var.get()
        if not in_path or not os.path.isfile(in_path):
            messagebox.showerror("Error", "Please select a valid file.")
            return

        replace = messagebox.askyesno("Replace original?",
                                      "Do you want to replace the original file with the encrypted file?\n"
                                      "Yes: Replace original\nNo: Choose where to save .enc")

        self.status.set("Encrypting...")
        self.root.update_idletasks()
        try:
            if replace:
                final_enc = encrypt_and_replace_original(in_path, pw)
                messagebox.showinfo("Success", f"Encrypted file replaced original:\n{final_enc}")
            else:
                out_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                        initialfile=os.path.basename(in_path) + ".enc")
                if not out_path:
                    self.status.set("Ready")
                    return
                encrypt_file(in_path, out_path, pw)
                messagebox.showinfo("Success", f"Encrypted file saved as:\n{out_path}")

            self.status.set("Encryption complete.")
            self.file_var.set("")
            self.pw_var.set("")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
            self.status.set("Error during encryption.")

    # ---- Decrypt ----
    def on_decrypt(self):
        in_path = self.file_var.get().strip()
        pw = self.pw_var.get()
        if not in_path or not os.path.isfile(in_path):
            messagebox.showerror("Error", "Please select a valid encrypted file.")
            return
        out_path = filedialog.asksaveasfilename(initialfile="decrypted_" +
                                                os.path.splitext(os.path.basename(in_path))[0])
        if not out_path:
            return
        self.status.set("Decrypting...")
        self.root.update_idletasks()
        try:
            decrypt_file(in_path, out_path, pw)
            messagebox.showinfo("Success", f"Decrypted file saved as:\n{out_path}")
            self.status.set("Decryption complete.")
            self.file_var.set("")
            self.pw_var.set("")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
            self.status.set("Error during decryption.")

# ---- Run app ----
if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedEncryptor(root)
    root.mainloop()
