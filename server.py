import socket
import threading
import os
import shutil
import ssl
from datetime import datetime

import config
from users.user_manager import USER_DB_MANAGER

HOST = '127.0.0.1'  # Localhost
PORT = 2020         # Default FTP port
DATA_PORT = 2120    # Default FTP data port


class FTPServer:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = self.ssl_context.wrap_socket(self.server_socket, server_side=True)

        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.clients = {}
        self.commands = {
            "USER": self.handle_user,
            "PASS": self.handle_pass,
            "SIGNUP": self.handle_signup,
            "QUIT": self.handle_quit,
            "LIST": self.handle_list,
            "PORT": self.handle_port,
            "RETR": self.handle_retr,
            "STOR": self.handle_stor,
            "DELE": self.handle_dele,
            "MKD": self.handle_mkd,
            "RMD": self.handle_rmd,
            "PWD": self.handle_pwd,
            "CWD": self.handle_cwd,
            "CDUP": self.handle_cdup,
        }
        print(f"FTPS Server running on {self.host}:{self.port} with SSL/TLS")

    def handle_client(self, client_socket, client_address):
        try:
            client_socket.do_handshake()
            print(f"SSL handshake completed with {client_address}")
        except ssl.SSLError as e:
            print(f"SSL handshake failed with {client_address}: {e}")
            return

        client_id = client_address
        self.clients[client_id] = {
            "socket": client_socket,
            "data_address": None,
            "authenticated": False,
            "user": None,
        }

        client_socket.send(b"220 Welcome to FTPS Server\r\n")

        while True:
            try:
                command = client_socket.recv(1024).decode().strip()
                if not command:
                    break
                print(f"Command from {client_address}: {command}")

                self.dispatch_command(client_id, command)
            except Exception as e:
                print(f"Error handling client {client_address}: {e}")
                break

        del self.clients[client_id]
        client_socket.close()

    def dispatch_command(self, client_id, command):
        """
        Maps commands to handler functions dynamically.
        """
        client_context = self.clients[client_id]
        client_socket = client_context["socket"]

        command_parts = command.split(' ', 1)
        cmd = command_parts[0].upper()
        arg = command_parts[1] if len(command_parts) > 1 else None

        if cmd not in self.commands:
            self.send_message(client_socket, "502 Command not implemented")
            return

        if not client_context["authenticated"] and cmd not in ["USER", "PASS", "SIGNUP", "QUIT"]:
            self.send_message(client_socket, "530 Not logged in")
            return

        if cmd in ["LIST", "RETR", "STOR"] and not client_context["data_address"]:
            self.send_message(client_socket, "425 Use PORT or PASV first.")
            return

        if not arg and cmd in ["RETR", "STOR", "DELE", "MKD", "RMD", "CWD", "PORT", "SIGNUP"]:
            self.send_message(client_socket, "501 Syntax error in parameters or arguments.")
            return

        handler = self.commands.get(cmd)
        handler(client_id, arg)

    @staticmethod
    def send_message(sock: socket.socket, message: str) -> None:
        sock.send(f"{message}\r\n".encode())

    @staticmethod
    def secure_path(filepath: str) -> str:
        """
        Secures the provided filepath to ensure it is within the allowed server directory.
        Prevents directory traversal attacks by normalizing and validating the path.

        Args:
            filepath (str): The user-provided file path.

        Returns:
            str: A safe, validated file path within the server's root directory.
        """
        server_root = os.path.abspath("./server_storage")
        normalized_path = os.path.normpath(os.path.join(server_root, filepath))

        if not normalized_path.startswith(server_root):
            raise PermissionError("Attempted directory traversal detected.")

        return normalized_path

    @staticmethod
    def format_size(size: int) -> str:
        suffixes = [" GB", " MB", " KB", " B"]
        while suffixes and size > 1024:
            size //= 1024
            suffixes.pop()

        return str(size) + suffixes[-1]

    def handle_user(self, client_id: str, username: str) -> None:
        user = USER_DB_MANAGER.get_user(username)

        if user:
            self.clients[client_id]["user"] = user
            self.send_message(self.clients[client_id]["socket"], "331 Username OK, need password")
        else:
            self.send_message(self.clients[client_id]["socket"], "530 Invalid username")

    def handle_pass(self, client_id: str, password: str):
        client_socket = self.clients[client_id]["socket"]
        user = self.clients[client_id]["user"]

        if not user:
            self.send_message(client_socket, "503 Bad sequence of commands")
            return

        if user.password == password:
            self.clients[client_id]["authenticated"] = True
            self.send_message(client_socket, "230 User logged in")
        else:
            self.send_message(client_socket, "530 Invalid password")

    def handle_signup(self, client_id: str, arg: str):
        control_socket = self.clients[client_id]["socket"]

        try:
            username, password = arg.split(' ')
        except Exception as e:
            print(f"Error parsing SIGNUP command: {e}")
            self.send_message(control_socket, "501 Syntax error in parameters or arguments.")
            return

        new_user = USER_DB_MANAGER.create_user(username, password)

        if new_user:
            self.clients[client_id]["user"] = new_user
            self.clients[client_id]["authenticated"] = True
            self.send_message(control_socket, "User created successfully")
            return

        self.send_message(control_socket, "Username already exists")

    def handle_quit(self, client_id: str, _: str) -> None:
        self.send_message(self.clients[client_id]["socket"], "221 Goodbye")
        self.clients[client_id]["socket"].close()

    def handle_port(self, client_id: str, arg: str) -> None:
        try:
            parts = arg.split(',')
            ip_address = '.'.join(parts[:4])
            port = (int(parts[4]) << 8) + int(parts[5])
            if not (0 <= port <= 65535):
                raise ValueError("Port out of range")
            self.clients[client_id]["data_address"] = (ip_address, port)
            self.send_message(self.clients[client_id]["socket"], "200 PORT command successful.")
        except Exception as e:
            print(f"Error parsing PORT command: {e}")
            self.send_message(self.clients[client_id]["socket"], "501 Syntax error in parameters or arguments.")

    def accept_data_connection(self, client_id: str) -> ssl.SSLSocket:
        """
        Accepts an incoming data connection from the client and wraps it in SSL.
        """
        data_address = self.clients[client_id]["data_address"]

        if not data_address:
            raise ValueError("Data connection address not set. Use PORT or PASV first.")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
            raw_socket.connect(data_address)
            ssl_socket = self.ssl_context.wrap_socket(raw_socket, server_side=True)
            return ssl_socket

    def handle_list(self, client_id: str, directory_path: str) -> None:
        client_context = self.clients[client_id]
        client_socket = client_context["socket"]
        directory_path = directory_path or "."

        try:
            safe_path = self.secure_path(directory_path)

            if not os.path.isdir(safe_path):
                self.send_message(client_socket, "550 Not a valid directory.")
                return

            files = os.listdir(safe_path)
            response_lines = []

            for file in files:
                full_path = os.path.join(safe_path, file)
                if os.path.isfile(full_path):
                    file_type = "FILE"
                elif os.path.isdir(full_path):
                    file_type = "DIR"
                else:
                    file_type = "OTHER"

                size = self.format_size(os.path.getsize(full_path)) if os.path.isfile(full_path) else "-"
                modified_date = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d")
                response_lines.append(f"{file_type.ljust(5)} {size.ljust(7)} {modified_date}   {file}")

            response = "\r\n".join(response_lines) + "\r\n"
            self.send_message(client_socket, "150 Here comes the directory listing")

            with self.accept_data_connection(client_id) as data_socket:
                data_socket.send(response.encode())

            self.send_message(client_socket, "226 Directory send ok")
        except PermissionError:
            self.send_message(client_socket, "550 Permission denied.")
        except Exception as e:
            print(f"Error listing directory {directory_path}: {e}")
            self.send_message(client_socket, "450 Failed to list directory")

    def handle_retr(self, client_id: str, filepath: str):
        client_context = self.clients[client_id]
        client_socket = client_context["socket"]

        if not client_context["user"].can_read:
            self.send_message(client_socket, "550 Permission denied.")
            return

        try:
            if not os.path.isfile(filepath):
                self.send_message(client_socket, "550 Not a valid file.")

            safe_path = self.secure_path(filepath)
            self.send_message(client_socket, "150 Opening data connection for file transfer")

            with self.accept_data_connection(client_id) as data_socket:
                with open(safe_path, 'rb') as f:
                    while chunk := f.read(1024):
                        data_socket.send(chunk)

            self.send_message(client_socket, "226 Transfer complete")
        except PermissionError:
            self.send_message(client_socket, "550 Permission denied.")
        except Exception as e:
            print(f"Error retrieving file {filepath}: {e}")
            self.send_message(client_socket, "450 Failed to retrieve file")

    def handle_stor(self, client_id: str, filepath: str):
        client_context = self.clients[client_id]
        client_socket = client_context["socket"]

        if not client_context["user"].can_write:
            self.send_message(client_socket, "550 Permission denied.")
            return

        try:
            safe_path = self.secure_path(filepath)
            os.makedirs(os.path.dirname(safe_path), exist_ok=True)
            self.send_message(client_socket, "150 Ready to receive file")

            with self.accept_data_connection(client_id) as data_socket:
                with open(safe_path, 'wb') as file:
                    while data := data_socket.recv(1024):
                        file.write(data)

            self.send_message(client_socket, "226 File transfer complete")
        except PermissionError:
            self.send_message(client_socket, "550 Permission denied.")
        except Exception as e:
            print(f"Error storing file {filepath}: {e}")
            self.send_message(client_socket, "450 Failed to store file")

    def handle_dele(self, client_id, filepath):
        client_context = self.clients[client_id]
        client_socket = client_context["socket"]

        if not client_context["user"].can_delete:
            self.send_message(client_socket, "550 Permission denied.")
            return

        try:
            if not os.path.isfile(filepath):
                self.send_message(client_socket, "550 File not found or is not a file")
                return

            safe_path = self.secure_path(filepath)
            os.remove(safe_path)
            self.send_message(client_socket, "250 File deleted successfully")

        except PermissionError:
            self.send_message(client_socket, "550 Permission denied.")
        except Exception as e:
            print(f"Error deleting file {filepath}: {e}")
            self.send_message(client_socket, "450 File deletion failed")

    def handle_mkd(self, client_id: str, directory_path: str):
        client_socket = self.clients[client_id]["socket"]

        if not self.clients[client_id]["user"].can_create:
            self.send_message(client_socket, "550 Permission denied.")
            return

        try:
            safe_path = self.secure_path(directory_path)
            os.makedirs(safe_path, exist_ok=True)
            self.send_message(client_socket, "257 Directory created successfully.")
        except PermissionError:
            self.send_message(client_socket, "550 Permission denied.")
        except Exception as e:
            print(f"Error creating directory: {e}")
            self.send_message(client_socket, "550 Directory creation failed.")

    def handle_rmd(self, client_id, directory_path):
        client_socket = self.clients[client_id]["socket"]

        if not self.clients[client_id]["user"].can_delete:
            self.send_message(client_socket, "550 Permission denied.")
            return

        try:
            safe_path = self.secure_path(directory_path)
            if os.path.isdir(safe_path):
                shutil.rmtree(safe_path)
                self.send_message(client_socket, f"250 Directory '{directory_path}' removed successfully")
            else:
                self.send_message(client_socket, "550 Directory not found or is not a directory")
        except PermissionError:
            self.send_message(client_socket, "550 Permission denied.")
        except Exception as e:
            print(f"Error removing directory {directory_path}: {e}")
            self.send_message(client_socket, "450 Directory removal failed")

    def handle_pwd(self, client_id, _):
        client_socket = self.clients[client_id]["socket"]

        try:
            current_directory = os.getcwd()
            self.send_message(client_socket, f'257 "{current_directory}" is the current directory')
        except Exception as e:
            print(f"Error getting current directory: {e}")
            self.send_message(client_socket, "450 Failed to retrieve current directory")

    def handle_cwd(self, client_id, directory_path):
        client_socket = self.clients[client_id]["socket"]

        try:
            safe_path = self.secure_path(directory_path)
            os.chdir(safe_path)
            current_directory = os.getcwd()
            self.send_message(client_socket, f'250 Directory successfully changed to "{current_directory}"')

        except FileNotFoundError:
            self.send_message(client_socket, "550 Directory not found")
        except NotADirectoryError:
            self.send_message(client_socket, "550 Not a directory")
        except PermissionError:
            self.send_message(client_socket, "550 Permission denied")
        except Exception as e:
            print(f"Error changing directory {directory_path}: {e}")
            self.send_message(client_socket, "450 Failed to change directory")

    def handle_cdup(self, client_id, _):
        client_socket = self.clients[client_id]["socket"]

        try:
            os.chdir('..')
            current_directory = os.getcwd()
            self.send_message(client_socket,
                               f'200 Moved to parent directory. Current directory: "{current_directory}"')
        except Exception as e:
            print(f"Error moving to parent directory: {e}")
            self.send_message(client_socket, "450 Failed to move to parent directory")

    def run(self) -> None:
        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Connection from {client_address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_thread.start()


if __name__ == "__main__":
    os.makedirs("server_storage", exist_ok=True)
    ftp_server = FTPServer(HOST, PORT)
    ftp_server.run()
