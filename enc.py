import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import random
import time
import base64

# Modular exponentiation
def mod_exp(base, exp, mod):
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result

# Miller-Rabin primality test for larger numbers
def is_prime(n, k=5):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_exp(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Generate large prime numbers
def generate_prime(bits):
    while True:
        n = random.getrandbits(bits) | 1  # Ensure odd
        if is_prime(n):
            return n

# Custom RSA key generation with larger keys
def generate_rsa_keys(bits=512):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common public exponent
    d = pow(e, -1, phi)
    return (e, n), (d, n)

# Simplified SHA-like hash function
def custom_hash(message, modulus=2**32):
    hash_value = 0x811c9dc5  # Initial value
    for byte in message.encode('utf-8'):
        hash_value = (hash_value * 0x01000193) ^ byte
        hash_value %= modulus
    return hash_value

# Simplified substitution-permutation block cipher
def custom_encrypt_block(plaintext, key, iv):
    key_int = int.from_bytes(key.encode('utf-8'), 'big') % 256
    iv_int = int.from_bytes(iv.encode('utf-8'), 'big') % 256
    cipher = ""
    for i, char in enumerate(plaintext):
        # Substitution and permutation with key and IV
        temp = (ord(char) + key_int + (iv_int ^ i)) % 128
        cipher += chr(temp)
    return cipher

def custom_decrypt_block(ciphertext, key, iv):
    key_int = int.from_bytes(key.encode('utf-8'), 'big') % 256
    iv_int = int.from_bytes(iv.encode('utf-8'), 'big') % 256
    plain = ""
    for i, char in enumerate(ciphertext):
        temp = (ord(char) - key_int - (iv_int ^ i)) % 128
        plain += chr(temp)
    return plain

# Encrypt message
def encrypt_message(public_key, message, log_func):
    e, n = public_key
    sym_key = str(random.randint(1, n - 1))
    iv = ''.join(chr(random.randint(32, 126)) for _ in range(8))  # 8-char IV
    log_func(f"Generated sym_key: {sym_key}, IV: {iv}")
    
    encrypted_key = mod_exp(int(sym_key), e, n)
    log_func(f"Encrypted key: {encrypted_key}")
    
    # Pad message to 16 chars (simplified padding)
    padded_message = message + " " * (16 - len(message) % 16 if len(message) % 16 else 0)
    ciphertext = custom_encrypt_block(padded_message, sym_key, iv)
    encoded_ciphertext = base64.b64encode(ciphertext.encode('utf-8')).decode('ascii')
    log_func(f"Encoded ciphertext: {encoded_ciphertext}")
    
    hash_value = custom_hash(ciphertext)
    log_func(f"Hash: {hash_value}")
    
    # Include n to bind to this key pair
    return f"{n}:{encrypted_key}:{base64.b64encode(iv.encode('ascii')).decode('ascii')}:{encoded_ciphertext}:{hash_value}"

# Decrypt message
def decrypt_message(private_key, encrypted_data, log_func):
    try:
        d, n_priv = private_key
        n_pub, encrypted_key, encoded_iv, encoded_ciphertext, hash_value = encrypted_data.split(":")
        n_pub, encrypted_key, hash_value = int(n_pub), int(encrypted_key), int(hash_value)
        
        # Verify key pair match
        if n_pub != n_priv:
            return "Error: Public and private key pair do not match!"
        
        log_func(f"Parsing: n={n_pub}, encrypted_key={encrypted_key}, encoded_iv={encoded_iv}, encoded_ciphertext={encoded_ciphertext}, hash={hash_value}")
        
        sym_key_int = mod_exp(encrypted_key, d, n_priv)
        sym_key = str(sym_key_int)
        iv = base64.b64decode(encoded_iv).decode('ascii')
        log_func(f"Decrypted sym_key: {sym_key}, IV: {iv}")
        
        ciphertext = base64.b64decode(encoded_ciphertext).decode('utf-8')
        log_func(f"Decoded ciphertext: {ciphertext}")
        
        computed_hash = custom_hash(ciphertext)
        log_func(f"Computed hash: {computed_hash}")
        if computed_hash != hash_value:
            return "Integrity check failed!"
        
        plaintext = custom_decrypt_block(ciphertext, sym_key, iv).rstrip()  # Remove padding
        log_func(f"Decrypted plaintext: {plaintext}")
        return plaintext
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# GUI Application
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Encryption Tool")
        self.root.geometry("700x600")

        self.bits = tk.IntVar(value=512)  # Key size in bits
        self.public_key = None
        self.private_key = None

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        self.config_tab = ttk.Frame(self.notebook)
        self.crypto_tab = ttk.Frame(self.notebook)
        self.log_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.config_tab, text="Configuration")
        self.notebook.add(self.crypto_tab, text="Encryption/Decryption")
        self.notebook.add(self.log_tab, text="Log")

        self.status = tk.StringVar(value="Ready")
        tk.Label(root, textvariable=self.status, bd=1, relief="sunken", anchor="w").pack(fill="x", side="bottom")

        # Configuration Tab
        tk.Label(self.config_tab, text="Key Size (bits):").grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(self.config_tab, textvariable=self.bits, width=10).grid(row=0, column=1)

        tk.Button(self.config_tab, text="Generate Keys", command=self.generate_keys).grid(row=1, column=0, pady=5)
        tk.Button(self.config_tab, text="Load Keys from File", command=self.load_keys_file).grid(row=1, column=1)
        tk.Button(self.config_tab, text="Save Keys to File", command=self.save_keys_file).grid(row=1, column=2)

        self.key_display = tk.Text(self.config_tab, height=4, width=60, state='disabled')
        self.key_display.grid(row=2, column=0, columnspan=3, pady=5)

        # Encryption/Decryption Tab
        tk.Label(self.crypto_tab, text="Input (Message or Encrypted):").grid(row=0, column=0, padx=5, pady=5)
        self.message_entry = tk.Text(self.crypto_tab, height=6, width=60)
        self.message_entry.grid(row=0, column=1, columnspan=2)

        tk.Label(self.crypto_tab, text="Output:").grid(row=1, column=0, padx=5, pady=5)
        self.result_entry = tk.Text(self.crypto_tab, height=6, width=60)
        self.result_entry.grid(row=1, column=1, columnspan=2)

        tk.Button(self.crypto_tab, text="Encrypt", command=self.encrypt).grid(row=2, column=0, pady=5)
        tk.Button(self.crypto_tab, text="Decrypt", command=self.decrypt).grid(row=2, column=1)
        tk.Button(self.crypto_tab, text="Clear", command=self.clear_fields).grid(row=2, column=2)

        tk.Button(self.crypto_tab, text="Load Input", command=self.load_file).grid(row=3, column=0, pady=5)
        tk.Button(self.crypto_tab, text="Save Output", command=self.save_file).grid(row=3, column=1)
        tk.Button(self.crypto_tab, text="Copy Output", command=self.copy_result).grid(row=3, column=2)

        # Log Tab
        self.log = tk.Text(self.log_tab, height=15, width=80, state='disabled')
        self.log.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.log_event("Application started.")

    def log_event(self, message):
        self.log.configure(state='normal')
        self.log.insert(tk.END, f"[{time.ctime()}] {message}\n")
        self.log.configure(state='disabled')
        self.log.see(tk.END)
        self.status.set(message)

    def generate_keys(self):
        self.log_event("Generating keys (this may take a moment)...")
        self.public_key, self.private_key = generate_rsa_keys(self.bits.get())
        self.update_key_display()
        self.log_event("Keys generated.")

    def update_key_display(self):
        self.key_display.configure(state='normal')
        self.key_display.delete("1.0", tk.END)
        if self.public_key and self.private_key:
            self.key_display.insert(tk.END, f"Public Key: {self.public_key}\nPrivate Key: ({self.private_key[0]}, ...)")
        self.key_display.configure(state='disabled')

    def save_keys_file(self):
        if not self.public_key or not self.private_key:
            messagebox.showwarning("Warning", "Generate keys first!")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(f"Public Key e: {self.public_key[0]}\n")
                f.write(f"Public Key n: {self.public_key[1]}\n")
                f.write(f"Private Key d: {self.private_key[0]}\n")
                f.write(f"Private Key n: {self.private_key[1]}\n")
            self.log_event(f"Keys saved to {file_path}")

    def load_keys_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                    e = int(lines[0].split(":")[1].strip())
                    n_pub = int(lines[1].split(":")[1].strip())
                    d = int(lines[2].split(":")[1].strip())
                    n_priv = int(lines[3].split(":")[1].strip())
                    if n_pub != n_priv:
                        raise ValueError("Public and private n must match!")
                    self.public_key = (e, n_pub)
                    self.private_key = (d, n_priv)
                    self.update_key_display()
                    self.log_event(f"Keys loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load keys: {str(e)}")
                self.log_event(f"Key load failed: {str(e)}")

    def encrypt(self):
        if not self.public_key:
            messagebox.showwarning("Warning", "Generate or load keys first!")
            return
        message = self.message_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "Enter a message to encrypt!")
            return
        encrypted = encrypt_message(self.public_key, message, self.log_event)
        self.result_entry.delete("1.0", tk.END)
        self.result_entry.insert("1.0", encrypted)
        self.log_event("Message encrypted.")

    def decrypt(self):
        if not self.private_key:
            messagebox.showwarning("Warning", "Generate or load keys first!")
            return
        encrypted = self.result_entry.get("1.0", tk.END).strip()
        if not encrypted:
            encrypted = self.message_entry.get("1.0", tk.END).strip()
            if not encrypted:
                messagebox.showwarning("Warning", "No encrypted message to decrypt! Enter it in Input or Output.")
                return
            self.log_event("Decrypting from Input field.")
        else:
            self.log_event("Decrypting from Output field.")
        
        decrypted = decrypt_message(self.private_key, encrypted, self.log_event)
        self.result_entry.delete("1.0", tk.END)
        self.result_entry.insert("1.0", decrypted)
        self.log_event("Message decrypted.")

    def clear_fields(self):
        self.message_entry.delete("1.0", tk.END)
        self.result_entry.delete("1.0", tk.END)
        self.log_event("Fields cleared.")

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as f:
                content = f.read()
                self.message_entry.delete("1.0", tk.END)
                self.message_entry.insert("1.0", content)
                self.log_event(f"Loaded file: {file_path}")

    def save_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.result_entry.get("1.0", tk.END).strip())
                self.log_event(f"Saved to file: {file_path}")

    def copy_result(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.result_entry.get("1.0", tk.END).strip())
        self.log_event("Result copied to clipboard.")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()