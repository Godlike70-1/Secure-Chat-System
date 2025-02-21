import threading
import socket
import argparse
import os
import sys
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from cryptography.fernet import Fernet
import hashlib
import random
import re
def is_strong_password(password):
    """Checks if the password meets strong password criteria."""
    special_characters = r"[^\w]"  # Matches ANY non-alphanumeric character
    
    # Debugging output to see what's failing
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

BG_COLOR = "#222831"
TEXT_COLOR = "#ffffff"
ENTRY_BG = "#393E46"
BUTTON_COLOR = "#00ADB5"
FONT = ("Poppins", 12)
HEADER_FONT = ("Poppins", 18, "bold")

# Load encryption key
KEY_FILE = "secret.key"

def load_key():
    """Load the AES encryption key"""
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

key = load_key()
cipher = Fernet(key)

class Receive(threading.Thread):
    def __init__(self, sock, name):
        super().__init__()
        self.sock = sock
        self.name = name
        self.messages = None

    def run(self):
        """Receives and processes messages from the server."""
        while True:
            try:
                received_data = self.sock.recv(1024).decode()

                if received_data.startswith("MESSAGE"):
                    _, sender, encrypted_message = received_data.split(":", 2)

                    try:
                        decrypted_message = cipher.decrypt(encrypted_message.encode()).decode('utf-8')
                    except Exception as e:
                        print(f"[CLIENT] Decryption error: {e}")
                        continue  # Skip invalid messages
                
                    if decrypted_message:
                        if self.messages:
                            self.messages.config(state=tk.NORMAL)

                            if sender == "You → Everyone":
                                # Display as a broadcast message
                                self.messages.insert(tk.END, f"\n📢 [Broadcast] {decrypted_message}", "broadcast")
                                self.messages.tag_config("broadcast", font=("Poppins", 12, "bold"), foreground="yellow")
                            else:
                                # Normal direct message
                                self.messages.insert(tk.END, f"\n💬 {sender}: {decrypted_message}", "received")

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
                            
                            # Display system messages with bold formatting
                            self.messages.insert(tk.END, f"\n📢 {system_message}", "system")
                            self.messages.tag_config("system", font=("Poppins", 12, "bold"), foreground="blue")

                            self.messages.config(state=tk.DISABLED)
                            self.messages.yview(tk.END)


            except Exception as e:
                print(f"[CLIENT] Error receiving message: {e}")
                return

class Client:
    """Manages the client connection and GUI"""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.messages = None

        self.connect_to_server()

    def connect_to_server(self):
        """Attempts to connect to the chat server, with automatic reconnection handling."""
        while True:
            try:
                self.sock.connect((self.host, self.port))
                print(f"Connected to {self.host}:{self.port}")
                self.show_login_window()
                return
            except ConnectionRefusedError:
                print("[CLIENT] Connection failed. Retrying in 5 seconds...")
                time.sleep(5)  # Wait and retry


    def show_login_window(self):
        """Login & Registration Window with Forgot Password Feature"""
        self.window = tk.Tk()
        self.window.title("Secure Chat Login")
        self.window.geometry("400x350")
        self.window.configure(bg=BG_COLOR)

        tk.Label(self.window, text="Username:", bg=BG_COLOR, fg=TEXT_COLOR, font=FONT).pack(pady=5)
        self.username_entry = tk.Entry(self.window, font=FONT, bg=ENTRY_BG, fg=TEXT_COLOR)
        self.username_entry.pack(pady=5)

        tk.Label(self.window, text="Password:", bg=BG_COLOR, fg=TEXT_COLOR, font=FONT).pack(pady=5)
        self.password_entry = tk.Entry(self.window, font=FONT, show="*", bg=ENTRY_BG, fg=TEXT_COLOR)
        self.password_entry.pack(pady=5)

        tk.Button(self.window, text="Login", bg=BUTTON_COLOR, fg=TEXT_COLOR, font=FONT, command=self.login).pack(pady=5)
        tk.Button(self.window, text="Register", bg=BUTTON_COLOR, fg=TEXT_COLOR, font=FONT, command=self.register).pack(pady=5)
        tk.Button(self.window, text="Forgot Password", bg="red", fg="white", font=FONT, command=self.forgot_password).pack(pady=5)
        tk.Button(self.window, text="Close", bg="red", fg="white", font=FONT, command=lambda:self.window.destroy()).pack(pady=5)
        self.window.mainloop()

    def forgot_password(self):
        """Opens a window for resetting the password."""
        username = simpledialog.askstring("Forgot Password", "Enter your username:")

        if not username:
            messagebox.showerror("Error", "Username cannot be empty!")
            return

        new_password = simpledialog.askstring("Reset Password", "Enter your new password:", show="*")
        confirm_password = simpledialog.askstring("Confirm Password", "Re-enter your new password:", show="*")

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
            messagebox.showinfo("Success", "Your password has been reset. Please log in.")
        elif response == "RESET_FAILED":
            messagebox.showerror("Error", "User not found. Please check your username.")
        else:
            messagebox.showerror("Error", "Failed to reset password. Try again later.")

    def login(self):
        """Handles user login with OTP verification and opens the chat window"""
        self.username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not self.username or not password:
            messagebox.showerror("Error", "Fields cannot be empty!")
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            print(f"[CLIENT] Sending Login Request: {self.username}")
            self.sock.send(f"LOGIN:{self.username}:{hashed_password}".encode())

            self.sock.settimeout(5)  # Set timeout to prevent freezing
            response = self.sock.recv(1024).decode()

            print(f"[CLIENT] Server Response: {response}")

            if response.startswith("OTP_REQUIRED"):
                sent_otp = response.split(":")[1]
                print(f"[CLIENT] OTP (Check Server Console): {sent_otp}")  # Show OTP

                # Ask user to manually enter the OTP
                user_otp = simpledialog.askstring("OTP Verification", "Enter the OTP shown in the server console:")

                self.sock.send(f"OTP_VERIFY:{self.username}:{user_otp}:{sent_otp}".encode())
                verification_response = self.sock.recv(1024).decode()

                if verification_response == "LOGIN_SUCCESS":
                    messagebox.showinfo("Success", "Login Successful!")

                    # Reset timeout and open chat window
                    self.sock.settimeout(None)
                    self.window.destroy()
                    self.open_chat_window()  # Open chat window immediately

                else:
                    messagebox.showerror("Error", "OTP Verification Failed!")

            elif response == "LOGIN_FAILED":
                messagebox.showerror("Error", "Invalid Username or Password. Try again.")

            else:
                messagebox.showerror("Error", "Unexpected Server Response!")

        except socket.timeout:
            messagebox.showerror("Error", "Login timed out. Please try again.")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")

    def register(self):
        """Handles user registration with email input and strong password validation."""
        self.username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        # Ask for email separately
        email = simpledialog.askstring("Email Required", "Enter your email for verification:")

        if not self.username or not password or not email:
            messagebox.showerror("Error", "All fields (Username, Email, Password) must be filled!")
            return

        if not is_strong_password(password):
            messagebox.showerror("Error", "Password must be at least 8 characters long and contain:\n"
                                        "- One uppercase letter\n"
                                        "- One lowercase letter\n"
                                        "- One number\n"
                                        "- At least one special character (e.g., @, #, $, %, &, *, etc.)")
            return
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            print(f"[CLIENT] Sending Registration Request: {self.username} with Email: {email}")
            self.sock.send(f"REGISTER:{self.username}:{email}:{hashed_password}".encode())

            # Set a timeout for receiving response
            self.sock.settimeout(5)  # 5 seconds timeout
            response = self.sock.recv(1024).decode()

            print(f"[CLIENT] Server Response: {response}")

            if response == "REGISTER_SUCCESS":
                messagebox.showinfo("Success", "Registration successful! Please login manually.")
                self.sock.settimeout(None)  # Reset timeout for future requests
            elif response == "REGISTER_FAILED:USERNAME_EXISTS":
                messagebox.showerror("Error", "Username or email already exists. Try another one.")
            elif response == "REGISTER_FAILED:WEAK_PASSWORD":
                messagebox.showerror("Error", "Weak password! Please follow the password rules.")
            else:
                messagebox.showerror("Error", "Unknown error occurred during registration. Try again.")

        except socket.timeout:
            messagebox.showerror("Error", "Server did not respond. Please try again later.")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")


    def send_message(self, textInput):
        """Encrypts and sends a message to the chat server, displaying it in the sender's chat window."""
        message = textInput.get().strip()
        textInput.delete(0, tk.END)

        if not message:
            return

        receiver = simpledialog.askstring("Recipient", "Enter the recipient username:\nType * to send to everyone.")

        if not receiver:
            messagebox.showerror("Error", "Recipient cannot be empty!")
            return

        if receiver == "*":
            confirmation = messagebox.askyesno("Broadcast Message", "Are you sure you want to send this message to everyone?")
            if not confirmation:
                return


        encrypted_message = cipher.encrypt(message.encode()).decode('utf-8')

        try:
            self.sock.sendall(f"MESSAGE:{self.username}:{receiver}:{encrypted_message}".encode())


            # Display the message in the sender’s chat window
            self.messages.config(state=tk.NORMAL)
            self.messages.insert(tk.END, f"\n🟢 You → {receiver}: {message}", "sent")
            self.messages.tag_config("sent", font=("Poppins", 12, "italic"))  # Italic font for sent messages
            self.messages.config(state=tk.DISABLED)
            self.messages.yview(tk.END)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")


    def open_chat_window(self):
        """Opens the chat window after successful login."""
        self.window = tk.Tk()
        self.window.title("Secure Chat")
        self.window.geometry("600x600")
        self.window.configure(bg=BG_COLOR)

        self.messages = scrolledtext.ScrolledText(self.window, state=tk.DISABLED, bg=ENTRY_BG, fg=TEXT_COLOR, font=FONT)
        self.messages.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.receiver_thread = Receive(self.sock, self.username)
        self.receiver_thread.messages = self.messages  # Pass reference to GUI messages
        self.receiver_thread.start()

        text_input = tk.Entry(self.window, font=FONT, bg=TEXT_COLOR, fg=BG_COLOR)
        text_input.pack(fill=tk.X, padx=10, pady=5)
        text_input.bind("<Return>", lambda event: self.send_message(text_input))

        tk.Button(self.window, text="Send", bg=BUTTON_COLOR, fg=TEXT_COLOR, font=FONT,
                command=lambda: self.send_message(text_input)).pack(pady=5)

        tk.Button(self.window, text="Close Chat", bg="Red", fg=TEXT_COLOR, font=FONT,
                command=lambda: self.window.destroy()).pack(pady=5)

        self.window.mainloop()

    def received_message(self):
        """Receives encrypted messages from the server and decrypts them."""
        while True:
            try:
                received_data = self.sock.recv(1024).decode()

                if received_data.startswith("MESSAGE"):
                    _, sender, encrypted_message = received_data.split(":", 2)

                    try:
                        decrypted_message = cipher.decrypt(encrypted_message.encode()).decode('utf-8')
                    except Exception as e:
                        print(f"Decryption error: {e}")
                        continue  # Skip invalid messages

                    if decrypted_message:
                        if self.messages:
                            self.messages.config(state=tk.NORMAL)
                            self.messages.insert(tk.END, f"\n💬 {sender}: {decrypted_message}", "received")
                            self.messages.config(state=tk.DISABLED)
                            self.messages.yview(tk.END)

                elif received_data.startswith("SYSTEM"):
                    _, system_message = received_data.split(":", 1)
                    self.messages.config(state=tk.NORMAL)
                    self.messages.insert(tk.END, f"\n🔔 {system_message}", "system")
                    self.messages.config(state=tk.DISABLED)
                    self.messages.yview(tk.END)

            except Exception as e:
                print(f"Error receiving message: {e}")
                return






if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument('host', help="Server IP Address")
    parser.add_argument('-p', metavar='PORT', type=int, default=1060, help="TCP port (default 1060)")

    args = parser.parse_args()
    Client(args.host, args.p)
