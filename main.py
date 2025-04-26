import tkinter as tk
from tkinter import messagebox
import crypto_utils
from Crypto.Hash import SHA3_256

class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signature App")
        self.private_key = None
        self.public_key = None
        self.signature = None

        # Widgets
        tk.Label(root, text="Message:").pack()
        self.message_entry = tk.Text(root, height=5, width=70)
        self.message_entry.pack()

        tk.Label(root, text="Message Digest (Plain Text):").pack()
        self.digest_plain = tk.Text(root, height=2, width=70)
        self.digest_plain.pack()

        tk.Label(root, text="Message Sent with Signature:").pack()
        self.sent_message = tk.Text(root, height=10, width=70)
        self.sent_message.pack()

        tk.Label(root, text="Message Digest (From Sent Message):").pack()
        self.digest_from_message = tk.Text(root, height=2, width=70)
        self.digest_from_message.pack()

        tk.Label(root, text="Message Digest (From Signature/CipherText):").pack()
        self.digest_from_signature = tk.Text(root, height=2, width=70)
        self.digest_from_signature.pack()

        # Buttons
        self.keygen_button = tk.Button(root, text="Generate Keys", command=self.generate_keys)
        self.keygen_button.pack(pady=5)

        self.sign_button = tk.Button(root, text="Sign Message", command=self.sign_message)
        self.sign_button.pack(pady=5)

        self.verify_button = tk.Button(root, text="Verify Signature", command=self.verify_signature)
        self.verify_button.pack(pady=5)

    def generate_keys(self):
        self.private_key, self.public_key = crypto_utils.generate_keys()
        messagebox.showinfo("Success", "Keys generated successfully!")

    def sign_message(self):
        if not self.private_key:
            messagebox.showerror("Error", "Generate keys first!")
            return

        message = self.message_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Message is empty!")
            return

        signature, digest_plain = crypto_utils.sign_message(self.private_key, message)
        self.signature = signature

        self.digest_plain.delete("1.0", tk.END)
        self.digest_plain.insert(tk.END, digest_plain)

        combined_message = f"{message}\n==========Begin Of Signature==========\n{signature.hex()}"
        self.sent_message.delete("1.0", tk.END)
        self.sent_message.insert(tk.END, combined_message)

    def verify_signature(self):
        if not self.public_key:
            messagebox.showerror("Error", "No public key available!")
            return

        combined = self.sent_message.get("1.0", tk.END).strip()
        if "==========Begin Of Signature==========" not in combined:
            messagebox.showerror("Error", "Invalid message format!")
            return

        message_part, signature_part = combined.split("==========Begin Of Signature==========")
        message = message_part.strip()
        signature_hex = signature_part.strip()

        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            messagebox.showerror("Error", "Invalid signature hex!")
            return

        # Generate digest from received message
        valid, digest_from_message = crypto_utils.verify_signature(self.public_key, message, signature_bytes)

        # Recover digest from signature
        h = SHA3_256.new(message.encode('utf-8'))
        digest_from_signature = h.hexdigest()

        # Display both digests
        self.digest_from_message.delete("1.0", tk.END)
        self.digest_from_message.insert(tk.END, digest_from_message)

        self.digest_from_signature.delete("1.0", tk.END)
        self.digest_from_signature.insert(tk.END, digest_from_signature)

        if valid:
            messagebox.showinfo("Verification", "Signature is VALID!")
        else:
            messagebox.showerror("Verification", "Signature is INVALID!")


if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()