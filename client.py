import threading
import socket
import argparse
import os
import sys
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, ttk
from cryptography.fernet import Fernet
import hashlib
import random
import re

def is_strong_password(password):
    """Checks if the password meets strong password criteria."""
    special_characters = r"[^\w]"  
    print(f"DEBUG: Checking password: {password}")
    if len(password) < 8:
        print("DEBUG: Password too short.")
        return False
    if not re.search(r'[A-Z]', password):
        print("DEBUG: Missing uppercase letter.")
        return False
    if not re.search(r'[a-z]', password):
        print("DEBUG: Missing lowercase letter.")
        return False
    if not re.search(r'\d', password):
        print("DEBUG: Missing number.")
        return False
    if not re.search(special_characters, password):
        print("DEBUG: Missing special character.")
        return False
    print(" Password accepted.")
    return True

# Enhanced GUI Color Scheme and Fonts
BG_COLOR = "#1A1A2E"
TEXT_COLOR = "#E6E6E6"
ACCENT_COLOR = "#0F3460"
BUTTON_COLOR = "#E94560"
CHAT_BG = "#16213E"
FONT = ("Segoe UI", 11)
HEADER_FONT = ("Segoe UI", 14, "bold")
PRIVATE_COLOR = "#FF6B6B"  # Red for private messages on receiver's screen
PUBLIC_COLOR = "#FFFFFF"   # White for public (broadcast) messages on receiver's screen
SENT_COLOR = "#98FB98"     # Green for sent messages on sender's screen

KEY_FILE = "secret.key"

def load_key():
    """Load the AES encryption key"""
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

key = load_key()
cipher = Fernet(key)

class Receive(threading.Thread):
    def __init__(self, sock, name, client_instance):
        super().__init__()
        self.sock = sock
        self.name = name
        self.messages = None
        self.client = client_instance

    def run(self):
        while True:
            try:
                received_data = self.sock.recv(4096).decode()
                if received_data.startswith("MESSAGE"):
                    parts = received_data.split(":", 4)
                    if len(parts) < 4:
                        print(f"[CLIENT] Invalid message format: {received_data}")
                        continue
                    _, sender, receiver, encrypted_message = parts[:4]
                    try:
                        decrypted_message = cipher.decrypt(encrypted_message.encode()).decode('utf-8')
                    except Exception as e:
                        print(f"[CLIENT] Decryption error: {e}")
                        continue  
                    if decrypted_message and self.messages:
                        self.messages.config(state=tk.NORMAL)
                        if sender.startswith("You →"):
                            # Sent message (public or private)
                            prefix = f"🟢 {sender}"
                            tag = "sent"
                            self.messages.insert(tk.END, f"\n{prefix}: {decrypted_message}", tag)
                            self.messages.tag_config("sent", foreground=SENT_COLOR, font=(FONT[0], 11, "italic"))
                        else:
                            # Received message
                            if receiver == "*":
                                prefix = f"📢 [Broadcast] {sender}"
                                tag = "broadcast"
                                self.messages.tag_config("broadcast", foreground=PUBLIC_COLOR, font=(FONT[0], 11, "bold"))
                            else:
                                prefix = f"💬 {sender}"
                                tag = "private"
                                self.messages.tag_config("private", foreground=PRIVATE_COLOR)
                            self.messages.insert(tk.END, f"\n{prefix}: {decrypted_message}", tag)
                        self.messages.config(state=tk.DISABLED)
                        self.messages.yview(tk.END)
                elif received_data.startswith("SYSTEM"):
                    try:
                        _, system_message = received_data.split(":", 1)
                    except ValueError:
                        print("[CLIENT] Error processing system message.")
                        return
                    if self.messages:
                        self.messages.config(state=tk.NORMAL)
                        self.messages.insert(tk.END, f"\n📢 {system_message}", "system")
                        self.messages.tag_config("system", foreground="#00CED1", font=(FONT[0], 11, "bold"))
                        self.messages.config(state=tk.DISABLED)
                        self.messages.yview(tk.END)
                elif received_data.startswith("HISTORY"):
                    try:
                        history_entries = received_data.split("\n")[1:]
                        if self.messages:
                            self.messages.config(state=tk.NORMAL)
                            for entry in history_entries:
                                if entry.strip():
                                    try:
                                        sender, receiver, encrypted_message, timestamp = entry.split(":", 3)
                                        decrypted_message = cipher.decrypt(encrypted_message.encode()).decode('utf-8')
                                        if receiver == "*" or receiver == self.name or sender == self.name:
                                            if sender == self.name:
                                                prefix = f"🟢 You → {receiver}"
                                                tag = "sent"
                                                self.messages.tag_config("sent", foreground=SENT_COLOR, font=(FONT[0], 11, "italic"))
                                            else:
                                                if receiver == "*":
                                                    prefix = f"📢 [Broadcast] {sender}"
                                                    tag = "broadcast"
                                                    self.messages.tag_config("broadcast", foreground=PUBLIC_COLOR, font=(FONT[0], 11, "bold"))
                                                else:
                                                    prefix = f"💬 {sender}"
                                                    tag = "private"
                                                    self.messages.tag_config("private", foreground=PRIVATE_COLOR)
                                            self.messages.insert(tk.END, 
                                                               f"\n[{timestamp}] {prefix}: {decrypted_message}", 
                                                               tag)
                                    except Exception as e:
                                        print(f"[CLIENT] Error processing history entry: {e}")
                            self.messages.config(state=tk.DISABLED)
                            self.messages.yview(tk.END)
                    except Exception as e:
                        print(f"[CLIENT] Error processing history: {e}")
                elif received_data.startswith("USER_COUNT"):
                    _, count = received_data.split(":")
                    if self.client.user_count_label:
                        self.client.user_count_label.config(text=f"Online: {count}")

            except Exception as e:
                print(f"[CLIENT] Error receiving message: {e}")
                return

class Client:
    """Manages the client connection and enhanced GUI"""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.messages = None
        self.user_count_label = None
        self.connect_to_server()

    def connect_to_server(self):
        """Attempts to connect to the chat server"""
        while True:
            try:
                self.sock.connect((self.host, self.port))
                print(f"Connected to {self.host}:{self.port}")
                self.show_login_window()
                return
            except ConnectionRefusedError:
                print("[CLIENT] Connection failed. Retrying in 5 seconds...")
                time.sleep(5)

    def show_login_window(self):
        """Enhanced Login & Registration Window"""
        self.window = tk.Tk()
        self.window.title("Secure Chat - Login")
        self.window.geometry("450x500")
        self.window.configure(bg=BG_COLOR)
        self.window.resizable(False, False)

        header_frame = tk.Frame(self.window, bg=ACCENT_COLOR, pady=20)
        header_frame.pack(fill="x")
        tk.Label(header_frame, text="Secure Chat", font=("Segoe UI", 20, "bold"), 
                bg=ACCENT_COLOR, fg=TEXT_COLOR).pack()

        main_frame = tk.Frame(self.window, bg=BG_COLOR, padx=40, pady=20)
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Username", bg=BG_COLOR, fg=TEXT_COLOR, 
                font=HEADER_FONT).pack(pady=(0, 5))
        self.username_entry = ttk.Entry(main_frame, font=FONT, style="Custom.TEntry")
        self.username_entry.pack(fill="x", pady=(0, 15))

        tk.Label(main_frame, text="Password", bg=BG_COLOR, fg=TEXT_COLOR, 
                font=HEADER_FONT).pack(pady=(0, 5))
        self.password_entry = ttk.Entry(main_frame, font=FONT, show="*", 
                                      style="Custom.TEntry")
        self.password_entry.pack(fill="x", pady=(0, 20))

        style = ttk.Style()
        style.configure("Custom.TButton", font=FONT, padding=8)
        style.configure("Custom.TEntry", padding=5)
        
        btn_frame = tk.Frame(main_frame, bg=BG_COLOR)
        btn_frame.pack(fill="x")
        
        ttk.Button(btn_frame, text="Login", style="Custom.TButton", 
                  command=self.login).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Register", style="Custom.TButton", 
                  command=self.register).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Forgot Password", style="Custom.TButton", 
                  command=self.forgot_password).pack(side="left", padx=5)
        
        ttk.Button(main_frame, text="Close", style="Custom.TButton", 
                  command=self.window.destroy).pack(pady=20)

        self.window.mainloop()

    def forgot_password(self):
        """Enhanced password reset window"""
        username = simpledialog.askstring("Forgot Password", "Enter your username:", 
                                       parent=self.window)
        if not username:
            messagebox.showerror("Error", "Username cannot be empty!")
            return

        new_password = simpledialog.askstring("Reset Password", "Enter your new password:", 
                                           show="*", parent=self.window)
        confirm_password = simpledialog.askstring("Confirm Password", "Re-enter your new password:", 
                                               show="*", parent=self.window)

        if not new_password or not confirm_password:
            messagebox.showerror("Error", "Password fields cannot be empty!")
            return

        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
        self.sock.send(f"RESET_PASSWORD:{username}:{hashed_password}".encode())
        response = self.sock.recv(1024).decode()

        if response == "RESET_SUCCESS":
            messagebox.showinfo("Success", "Password reset successful. Please log in.")
        elif response == "RESET_FAILED":
            messagebox.showerror("Error", "User not found. Please check your username.")
        else:
            messagebox.showerror("Error", "Failed to reset password.")

    def login(self):
        """Handles user login with OTP verification"""
        self.username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not self.username or not password:
            messagebox.showerror("Error", "Fields cannot be empty!")
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            print(f"[CLIENT] Sending Login Request: {self.username}")
            self.sock.send(f"LOGIN:{self.username}:{hashed_password}".encode())
            self.sock.settimeout(5)
            response = self.sock.recv(1024).decode()
            print(f"[CLIENT] Server Response: {response}")

            if response.startswith("OTP_REQUIRED"):
                sent_otp = response.split(":")[1]
                messagebox.showinfo("OTP Received", 
                                  f"Your OTP is: {sent_otp}\nPlease enter it in the next dialog.",
                                  parent=self.window)
                print(f"[CLIENT] OTP: {sent_otp}")
                
                user_otp = simpledialog.askstring("OTP Verification", 
                                               "Enter the OTP shown in the previous dialog:",
                                               parent=self.window)
                if not user_otp:
                    messagebox.showerror("Error", "OTP cannot be empty!")
                    return

                self.sock.send(f"OTP_VERIFY:{self.username}:{user_otp}:{sent_otp}".encode())
                verification_response = self.sock.recv(1024).decode()

                if verification_response == "LOGIN_SUCCESS":
                    messagebox.showinfo("Success", "Login Successful!")
                    self.sock.settimeout(None)
                    self.window.destroy()
                    self.open_chat_window()
                else:
                    messagebox.showerror("Error", "OTP Verification Failed!")
            elif response == "LOGIN_FAILED":
                messagebox.showerror("Error", "Invalid credentials!")
            else:
                messagebox.showerror("Error", "Unexpected server response!")
        except socket.timeout:
            messagebox.showerror("Error", "Login timed out!")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")

    def register(self):
        """Handles user registration"""
        self.username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        email = simpledialog.askstring("Email Required", "Enter your email:", 
                                     parent=self.window)
        
        if not self.username or not password or not email:
            messagebox.showerror("Error", "All fields must be filled!")
            return
        
        if not is_strong_password(password):
            messagebox.showerror("Error", "Password must contain:\n- 8+ characters\n- Uppercase\n- Lowercase\n- Number\n- Special character")
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            self.sock.send(f"REGISTER:{self.username}:{email}:{hashed_password}".encode())
            self.sock.settimeout(5)
            response = self.sock.recv(1024).decode()

            if response == "REGISTER_SUCCESS":
                messagebox.showinfo("Success", "Registration successful! Please login.")
                self.sock.settimeout(None)
            elif response == "REGISTER_FAILED:USERNAME_EXISTS":
                messagebox.showerror("Error", "Username or email already exists!")
            else:
                messagebox.showerror("Error", "Registration failed!")
        except socket.timeout:
            messagebox.showerror("Error", "Server timeout!")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")

    def send_message(self, text_input):
        """Encrypts and sends messages"""
        message = text_input.get().strip()
        text_input.delete(0, tk.END)
        if not message:
            return
        
        receiver = simpledialog.askstring("Recipient", 
                                        "Enter recipient username (* for everyone):",
                                        parent=self.window)
        if not receiver:
            messagebox.showerror("Error", "Recipient cannot be empty!")
            return
        
        if receiver == "*":
            if not messagebox.askyesno("Broadcast", "Send to everyone?"):
                return

        encrypted_message = cipher.encrypt(message.encode()).decode('utf-8')
        try:
            self.sock.sendall(f"MESSAGE:{self.username}:{receiver}:{encrypted_message}".encode())
            self.messages.config(state=tk.NORMAL)
            self.messages.insert(tk.END, f"\n🟢 You → {receiver}: {message}", "sent")
            self.messages.tag_config("sent", foreground=SENT_COLOR, font=(FONT[0], 11, "italic"))
            self.messages.config(state=tk.DISABLED)
            self.messages.yview(tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send: {e}")

    def request_message_history(self):
        """Request message history from the server"""
        try:
            self.sock.send(f"HISTORY:{self.username}".encode())
            print(f"[CLIENT] Requested message history for {self.username}")
        except Exception as e:
            print(f"[CLIENT] Error requesting history: {e}")

    def open_chat_window(self):
        """Enhanced chat window with user count display"""
        self.window = tk.Tk()
        self.window.title(f"Secure Chat - {self.username}")
        self.window.geometry("700x600")
        self.window.configure(bg=BG_COLOR)
        self.window.resizable(True, True)

        header_frame = tk.Frame(self.window, bg=ACCENT_COLOR, pady=10)
        header_frame.pack(fill="x")
        tk.Label(header_frame, text=f"Welcome, {self.username}", font=HEADER_FONT,
                bg=ACCENT_COLOR, fg=TEXT_COLOR).pack(side="left", padx=10)
        
        status_frame = tk.Frame(self.window, bg=ACCENT_COLOR, pady=5)
        status_frame.pack(fill="x")
        tk.Label(status_frame, text="Connected", font=FONT, bg=ACCENT_COLOR,
                fg="#98FB98").pack(side="left", padx=10)
        self.user_count_label = tk.Label(status_frame, text="Online: 0", font=FONT, 
                                       bg=ACCENT_COLOR, fg="#FFD700")
        self.user_count_label.pack(side="right", padx=10)

        self.messages = scrolledtext.ScrolledText(self.window, state=tk.DISABLED, 
                                               bg=CHAT_BG, fg=TEXT_COLOR, font=FONT,
                                               wrap=tk.WORD, borderwidth=0)
        self.messages.pack(fill="both", expand=True, padx=10, pady=10)

        input_frame = tk.Frame(self.window, bg=BG_COLOR, pady=10)
        input_frame.pack(fill="x", padx=10)
        
        text_input = ttk.Entry(input_frame, font=FONT, style="Custom.TEntry")
        text_input.pack(side="left", fill="x", expand=True, padx=(0, 10))
        text_input.bind("<Return>", lambda event: self.send_message(text_input))

        ttk.Button(input_frame, text="Send", style="Custom.TButton",
                  command=lambda: self.send_message(text_input)).pack(side="left")
        
        ttk.Button(input_frame, text="Close", style="Custom.TButton",
                  command=self.window.destroy).pack(side="right")

        self.receiver_thread = Receive(self.sock, self.username, self)
        self.receiver_thread.messages = self.messages
        self.receiver_thread.start()

        self.request_message_history()

        self.window.mainloop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument('host', help="Server IP Address")
    parser.add_argument('-p', metavar='PORT', type=int, default=1060, 
                       help="TCP port (default 1060)")
    args = parser.parse_args()
    Client(args.host, args.p)