import threading
import socket
import mysql.connector
import hashlib
import os
import smtplib
import random
from email.mime.text import MIMEText
from cryptography.fernet import Fernet
import re
import datetime

# Load Encryption Key
KEY_FILE = "secret.key"

def is_strong_password(password):
    """Checks if the password meets strong password criteria."""
    special_characters = r"[^\w]"
    print(f"DEBUG: Checking password: {password}")
    if len(password) < 8:
        print("DEBUG: Password too short.")
        return False
    print("DEBUG: Password accepted.")
    return True

def load_key():
    """Load the encryption key from a file."""
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

key = load_key()
cipher = Fernet(key)

class ChatServer:
    """ Secure Chat Server with User Authentication & Chat History """

    def __init__(self, host="localhost", port=1060):
        self.host = host
        self.port = port
        self.clients = {}
        self.db = self.connect_database()

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

    def connect_database(self):
        """Connects to the MySQL database."""
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="",  # Update with your MySQL password
            database="chat_app"
        )

    def hash_password(self, password, salt=None):
        """Hashes passwords securely with SHA-256."""
        if salt is None:
            salt = os.urandom(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt.hex(), hashed.hex()

    def send_otp(self, email):
        """Sends an OTP to the user's email for secure login."""
        otp = str(random.randint(100000, 999999))
        subject = "Your Secure Chat OTP Code"
        body = f"Your OTP for login is: {otp}"

        msg = MIMEText(body)
        msg["From"] = "your_email@gmail.com"
        msg["To"] = email
        msg["Subject"] = subject

        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login("your_email@gmail.com", "your_email_password")  # Update with correct credentials
            server.sendmail("your_email@gmail.com", email, msg.as_string())
            server.quit()
            return otp
        except smtplib.SMTPAuthenticationError:
            print("[SERVER] SMTP Authentication Error: Check your email credentials.")
            return None
        except Exception as e:
            print(f"[SERVER] Failed to send OTP: {e}")
            return None

    def broadcast_user_count(self):
        """Sends the current number of connected users to all clients."""
        user_count = len(self.clients)
        message = f"USER_COUNT:{user_count}"
        for user, conn in self.clients.items():
            try:
                conn.sendall(message.encode())
            except Exception as e:
                print(f"[SERVER] Error sending user count to {user}: {e}")

    def handle_client(self, client_socket):
        """Handles user authentication, OTP verification, message transmission, and history retrieval."""
        username = None

        while True:
            try:
                data = client_socket.recv(4096).decode()
                if not data:
                    break

                elif data.startswith("REGISTER"):
                    _, username, email, password = data.split(":")
                    print(f"[SERVER] Registration Request: {username} ({email})")

                    if not is_strong_password(password):
                        print("[SERVER] Registration Failed: Weak password")
                        client_socket.send("REGISTER_FAILED:WEAK_PASSWORD".encode())
                        continue

                    salt, hashed_password = self.hash_password(password)
                    cursor = self.db.cursor()
                    try:
                        cursor.execute("INSERT INTO users (username, email, password_hash, salt) VALUES (%s, %s, %s, %s)", 
                                       (username, email, hashed_password, salt))
                        self.db.commit()
                        print(f"[SERVER] User {username} Registered Successfully!")
                        client_socket.send("REGISTER_SUCCESS".encode())
                    except mysql.connector.IntegrityError as e:
                        print(f"[SERVER] Registration Failed: {e}")
                        client_socket.send("REGISTER_FAILED:USERNAME_EXISTS".encode())

                elif data.startswith("RESET_PASSWORD"):
                    _, username, new_password = data.split(":")
                    cursor = self.db.cursor()
                    cursor.execute("SELECT salt FROM users WHERE username=%s", (username,))
                    user = cursor.fetchone()

                    if not user:
                        client_socket.send("RESET_FAILED".encode())
                        continue

                    salt = bytes.fromhex(user[0])
                    _, new_hashed_password = self.hash_password(new_password, salt)
                    cursor.execute("UPDATE users SET password_hash=%s WHERE username=%s", 
                                   (new_hashed_password, username))
                    self.db.commit()
                    client_socket.send("RESET_SUCCESS".encode())

                elif data.startswith("LOGIN"):
                    _, username, password = data.split(":")
                    print(f"[SERVER] Login Request for: {username}")

                    cursor = self.db.cursor()
                    cursor.execute("SELECT password_hash, salt FROM users WHERE username=%s", (username,))
                    user = cursor.fetchone()

                    if user:
                        stored_hash, salt = user
                        _, computed_hash = self.hash_password(password, bytes.fromhex(salt))

                        if computed_hash == stored_hash:
                            otp = str(random.randint(100000, 999999))
                            print(f"[SERVER] OTP for {username}: {otp}")
                            client_socket.send(f"OTP_REQUIRED:{otp}".encode())
                        else:
                            client_socket.send("LOGIN_FAILED".encode())
                    else:
                        client_socket.send("LOGIN_FAILED".encode())

                elif data.startswith("OTP_VERIFY"):
                    _, username, otp, sent_otp = data.split(":")
                    if otp == sent_otp:
                        self.clients[username] = client_socket
                        client_socket.send("LOGIN_SUCCESS".encode())
                        print(f"[SERVER] User {username} successfully logged in.")

                        join_message = f"📢 {username} joined the chat!"
                        for user, conn in self.clients.items():
                            if user != username:
                                try:
                                    conn.send(f"SYSTEM:{join_message}".encode())
                                except Exception as e:
                                    print(f"[SERVER] Error sending join message to {user}: {e}")
                        self.broadcast_user_count()

                    else:
                        client_socket.send("OTP_FAILED".encode())

                elif data.startswith("MESSAGE"):
                    try:
                        _, sender, receiver, encrypted_message = data.split(":", 3)
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        cursor = self.db.cursor()
                        cursor.execute("INSERT INTO messages (sender, receiver, message, timestamp) VALUES (%s, %s, %s, %s)",
                                       (sender, receiver, encrypted_message, timestamp))
                        self.db.commit()

                        if receiver == "*":
                            for user, conn in self.clients.items():
                                if user != sender:
                                    try:
                                        conn.sendall(f"MESSAGE:{sender}:{receiver}:{encrypted_message}".encode())
                                        print(f"[SERVER] Broadcasted message from {sender} to {user}.")
                                    except Exception as e:
                                        print(f"[SERVER] Error sending broadcast message to {user}: {e}")
                            if sender in self.clients:
                                try:
                                    self.clients[sender].sendall(f"MESSAGE:You → Everyone:{receiver}:{encrypted_message}".encode())
                                except Exception as e:
                                    print(f"[SERVER] Error sending confirmation to sender: {e}")
                        else:
                            if receiver in self.clients:
                                try:
                                    self.clients[receiver].sendall(f"MESSAGE:{sender}:{receiver}:{encrypted_message}".encode())
                                    print(f"[SERVER] Private message sent from {sender} to {receiver}.")
                                except Exception as e:
                                    print(f"[SERVER] Error sending message to {receiver}: {e}")
                            if sender in self.clients:
                                try:
                                    self.clients[sender].sendall(f"MESSAGE:You → {receiver}:{receiver}:{encrypted_message}".encode())
                                except Exception as e:
                                    print(f"[SERVER] Error sending message confirmation to sender: {e}")
                        print(f"[SERVER] Message stored and sent from {sender} to {receiver}")

                    except Exception as e:
                        print(f"[SERVER] Error storing/sending message: {e}")

                elif data.startswith("HISTORY"):
                    _, username = data.split(":")
                    print(f"[SERVER] History request from {username}")
                    cursor = self.db.cursor()
                    cursor.execute("""
                        SELECT sender, receiver, message, timestamp 
                        FROM messages 
                        WHERE sender = %s OR receiver = %s OR receiver = '*'
                        ORDER BY timestamp ASC
                    """, (username, username))
                    messages = cursor.fetchall()

                    if messages:
                        history_response = "HISTORY\n" + "\n".join(
                            f"{sender}:{receiver}:{message}:{timestamp}"
                            for sender, receiver, message, timestamp in messages
                        )
                    else:
                        history_response = "HISTORY\nNo messages found."

                    try:
                        client_socket.sendall(history_response.encode())
                        print(f"[SERVER] Sent history to {username}")
                    except Exception as e:
                        print(f"[SERVER] Error sending history to {username}: {e}")

            except Exception as e:
                print(f"[SERVER] Error: {e}")
                if username and username in self.clients:
                    del self.clients[username]
                    self.broadcast_user_count()
                client_socket.close()
                break

    def run(self):
        """Accepts new clients and starts threads."""
        while True:
            client_socket, _ = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()

if __name__ == "__main__":
    ChatServer().run()