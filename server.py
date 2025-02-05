import socket
import threading
import os
import shutil
from datetime import datetime

from db_manager import USER_DB

HOST = '127.0.0.1'  # Localhost
PORT = 2020         # Default FTP port
DATA_PORT = 2120    # Default FTP data port


class FTPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.clients = {}
        print(f"FTP Server running on {self.host}:{self.port}")

    def handle_client(self, client_socket, client_address):
        client_id = client_address
        self.clients[client_id] = {
            "socket": client_socket,
            "data_address": None,
            "authenticated": False,
            "username": None,
        }

        client_socket.send(b"220 Welcome to FTP Server\r\n")

        while True:
            command = client_socket.recv(1024).decode().strip()
            if not command:
                break
            print(f"Received from {client_address}: {command}")

            client_context = self.clients[client_id]

            if command.upper().startswith('PORT'):
                try:
                    parts = command.split(' ')[1].split(',')
                    ip_address = '.'.join(parts[:4])
                    port = (int(parts[4]) << 8) + int(parts[5])
                    if not (0 <= port <= 65535):
                        raise ValueError("Port out of range")
                    self.clients[client_id]["data_address"] = (ip_address, port)
                    client_socket.send(b"200 PORT command successful.\r\n")
                except Exception as e:
                    print(f"Error parsing PORT command: {e}")
                    client_socket.send(b"501 Syntax error in parameters or arguments.\r\n")

            elif command.upper().startswith('USER'):
                username = command.split(' ')[1] if len(command.split()) > 1 else None
                if username in USER_DB:
                    self.clients[client_id]["username"] = username
                    client_socket.send(b"331 Username OK, need password.\r\n")
                else:
                    client_socket.send(b"530 Invalid username.\r\n")

            elif command.upper().startswith('PASS'):
                if not client_context["username"]:
                    client_socket.send(b"503 Bad sequence of commands.\r\n")
                    continue

                password = command.split(' ')[1] if len(command.split()) > 1 else None
                if USER_DB.get(client_context["username"]) == password:
                    self.clients[client_id]["authenticated"] = True
                    client_socket.send(b"230 User logged in.\r\n")
                else:
                    client_socket.send(b"530 Invalid password.\r\n")

            elif command.upper().startswith('LIST'):
                if not client_context["authenticated"]:
                    client_socket.send(b"530 Not logged in.\r\n")
                    continue

                if not client_context["data_address"]:
                    client_socket.send(b"425 Use PORT or PASV first.\r\n")
                    continue

                client_socket.send(b"150 Here comes the directory listing.\r\n")
                directory_path = command.split(' ')[1] if len(command.split()) > 1 else '.'

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
                    data_socket.connect(client_context["data_address"])
                    self.list_files(data_socket, directory_path)

                client_socket.send(b"226 Directory send ok.\r\n")

            elif command.upper().startswith('RETR'):
                if not client_context["authenticated"]:
                    client_socket.send(b"530 Not logged in.\r\n")
                    continue

                if not client_context["data_address"]:
                    client_socket.send(b"425 Use PORT or PASV first.\r\n")
                    continue

                filepath = command.split(' ')[1]
                client_socket.send(b"150 Opening data connection for file transfer.\r\n")

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
                    data_socket.connect(client_context["data_address"])
                    if self.send_file(data_socket, filepath):
                        client_socket.send(b"226 Transfer complete.\r\n")
                    else:
                        client_socket.send(b"550 File not found.\r\n")

            elif command.upper().startswith('STOR'):
                if not client_context["authenticated"]:
                    client_socket.send(b"530 Not logged in.\r\n")
                    continue

                if not client_context["data_address"]:
                    client_socket.send(b"425 Use PORT or PASV first.\r\n")
                    continue

                filepath = command.split(' ', 1)[1] if len(command.split()) > 1 else None
                if not filepath:
                    client_socket.send(b"501 Syntax error in parameters or arguments.\r\n")
                    continue

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_connection:
                    data_connection.connect(client_context["data_address"])
                    self.store_file(client_socket, filepath, data_connection)

            elif command.upper().startswith('DELE'):
                if not client_context["authenticated"]:
                    client_socket.send(b"530 Not logged in.\r\n")
                    continue

                filepath = command.split(' ', 1)[1] if len(command.split()) > 1 else None
                if not filepath:
                    client_socket.send(b"501 Syntax error in parameters or arguments.\r\n")
                    continue

                self.delete_file(client_socket, filepath)

            elif command.upper().startswith('MKD'):
                if not client_context["authenticated"]:
                    client_socket.send(b"530 Not logged in.\r\n")
                    continue

                directory_path = command.split(' ', 1)[1] if len(command.split()) > 1 else None
                if not directory_path:
                    client_socket.send(b"501 Syntax error in parameters or arguments.\r\n")
                    continue

                self.make_directory(client_socket, directory_path)

            elif command.upper().startswith('RMD'):
                if not client_context["authenticated"]:
                    client_socket.send(b"530 Not logged in.\r\n")
                    continue

                directory_path = command.split(' ', 1)[1] if len(command.split()) > 1 else None
                if directory_path:
                    client_socket.send(b"501 Syntax error in parameters or arguments.\r\n")
                    continue

                self.remove_directory(client_socket, directory_path)

            elif command.upper() == 'PWD':
                if not client_context["authenticated"]:
                    client_socket.send(b"530 Not logged in.\r\n")
                    continue

                self.get_current_directory(client_socket)

            elif command.upper().startswith('CWD'):
                if not client_context["authenticated"]:
                    client_socket.send(b"530 Not logged in.\r\n")
                    continue

                directory_path = command.split(' ', 1)[1] if len(command.split()) > 1 else None
                if not directory_path:
                    client_socket.send(b"501 Syntax error in parameters or arguments.\r\n")
                    continue

                self.change_directory(client_socket, directory_path)

            elif command.upper() == 'CDUP':
                if not client_context["authenticated"]:
                    client_socket.send(b"530 Not logged in.\r\n")
                    continue

                self.change_to_parent_directory(client_socket)

            elif command.upper() == 'QUIT':
                client_socket.send(b"221 Goodbye.\r\n")
                break

            else:
                if not client_context["authenticated"]:
                    client_socket.send(b"530 Not logged in.\r\n")
                else:
                    client_socket.send(b"502 Command not implemented.\r\n")

        del self.clients[client_id]
        client_socket.close()

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

    def list_files(self, data_socket: socket.socket, directory_path: str = "./server_storage") -> None:
        """
        Sends a detailed list of files in the specified directory to the data socket.

        Args:
            data_socket (socket): The data socket used for sending the directory listing.
            directory_path (str): Path of the directory to list. Defaults to the current directory.
        """
        try:
            if not os.path.isdir(directory_path):
                data_socket.send(b"550 Not a valid directory.\r\n")
                return

            safe_path = self.secure_path(directory_path)
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
            data_socket.send(response.encode())
        except PermissionError:
            data_socket.send(b"550 Permission denied.\r\n")
        except Exception as e:
            data_socket.send(f"450 Error listing directory: {str(e)}\r\n".encode())

    def send_file(self, data_socket: socket.socket, filepath: str) -> bool:
        try:
            safe_path = self.secure_path(filepath)

            if not os.path.isfile(safe_path):
                return False

            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(1024)
                    if not data:
                        break
                    data_socket.send(data)

            return True

        except RuntimeError:
            return False
        finally:
            data_socket.close()

    def store_file(self, client_socket: socket.socket, filepath: str, data_connection: socket.socket) -> None:
        """
        Stores a file uploaded by the client to the server, ensuring the path is secure.
        """
        try:
            safe_path = self.secure_path(filepath)
            os.makedirs(os.path.dirname(safe_path), exist_ok=True)

            with open(safe_path, 'wb') as file:
                client_socket.send(b"150 Ready to receive file.\r\n")
                while data := data_connection.recv(1024):
                    file.write(data)

            client_socket.send(b"226 File transfer complete.\r\n")
        except PermissionError:
            client_socket.send(b"550 Permission denied.\r\n")
        except Exception as e:
            print(f"Error storing file: {e}")
            client_socket.send(b"450 Failed to store file.\r\n")
        finally:
            data_connection.close()

    def delete_file(self, client_socket: socket.socket, filepath: str) -> None:
        """
        Deletes a file on the server.
        """
        try:
            safe_path = self.secure_path(filepath)
            if os.path.isfile(safe_path):
                os.remove(safe_path)
                client_socket.send(b"250 File deleted successfully.\r\n")
            else:
                client_socket.send(b"550 File not found or is not a file.\r\n")
        except PermissionError:
            client_socket.send(b"550 Permission denied.\r\n")
        except Exception as e:
            print(f"Error deleting file: {e}")
            client_socket.send(b"450 File deletion failed.\r\n")

    @staticmethod
    def make_directory(client_socket: socket.socket, directory_path: str) -> None:
        """
        Creates a new directory on the server.
        """
        try:
            os.makedirs(directory_path, exist_ok=True)
            client_socket.send(b"257 Directory created successfully.\r\n")
        except Exception as e:
            print(f"Error creating directory: {e}")
            client_socket.send(b"550 Directory creation failed.\r\n")

    def remove_directory(self, client_socket: socket.socket, directory_path: str) -> None:
        """
        Removes a directory on the server.
        """
        try:
            safe_path = self.secure_path(directory_path)
            if os.path.isdir(safe_path):
                shutil.rmtree(directory_path)
                client_socket.send(b"250 Directory removed successfully.\r\n")
            else:
                client_socket.send(b"550 Directory not found or is not a directory.\r\n")
        except PermissionError:
            client_socket.send(b"550 Permission denied.\r\n")
        except Exception as e:
            print(f"Error removing directory: {e}")
            client_socket.send(b"450 Directory removal failed. Make sure it is empty.\r\n")

    @staticmethod
    def get_current_directory(client_socket: socket.socket) -> None:
        """
        Sends the current working directory to the client.
        """
        try:
            current_directory = os.getcwd()
            client_socket.send(f'257 "{current_directory}" is the current directory.\r\n'.encode())
        except Exception as e:
            print(f"Error getting current directory: {e}")
            client_socket.send(b"450 Failed to retrieve current directory.\r\n")

    def change_directory(self, client_socket: socket.socket, directory_path: str) -> None:
        """
        Changes the working directory to the specified path.
        """
        try:
            safe_path = self.secure_path(directory_path)
            os.chdir(safe_path)
            current_directory = os.getcwd()
            client_socket.send(f'250 Directory successfully changed to "{current_directory}".\r\n'.encode())
        except FileNotFoundError:
            client_socket.send(b"550 Directory not found.\r\n")
        except NotADirectoryError:
            client_socket.send(b"550 Not a directory.\r\n")
        except PermissionError:
            client_socket.send(b"550 Permission denied.\r\n")
        except Exception as e:
            print(f"Error changing directory: {e}")
            client_socket.send(b"450 Failed to change directory.\r\n")

    @staticmethod
    def change_to_parent_directory(client_socket: socket.socket) -> None:
        """
        Changes the working directory to the parent directory.
        """
        try:
            os.chdir('..')
            current_directory = os.getcwd()
            client_socket.send(f'200 Moved to parent directory. Current directory: "{current_directory}".\r\n'.encode())
        except Exception as e:
            print(f"Error moving to parent directory: {e}")
            client_socket.send(b"450 Failed to move to parent directory.\r\n")

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
