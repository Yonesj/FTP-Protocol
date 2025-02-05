import socket
import os
import sys


class FTPClient:
    def __init__(self, host: str, port: int, data_port: int = 0) -> None:
        self.host = host
        self.port = port
        self.data_port = data_port
        self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data_socket = None

    def connect(self) -> str:
        self.control_socket.connect((self.host, self.port))
        return self.control_socket.recv(1024).decode()

    def send_command(self, command: str) -> str:
        self.control_socket.send(f"{command}\r\n".encode())
        return self.control_socket.recv(1024).decode("ascii")

    def setup_data_connection(self) -> None:
        self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data_socket.bind(('', 0))
        self.data_socket.listen(1)
        assigned_port = self.data_socket.getsockname()[1]
        local_ip = socket.gethostbyname(socket.gethostname())
        self.send_command(f"PORT {local_ip.replace('.', ',')},{assigned_port >> 8},{assigned_port & 0xFF}")

    def list_files(self, command: str) -> str:
        self.setup_data_connection()
        result = self.send_command(command)

        if result.startswith("530") or result.startswith("425"):
            return

        data_conn, _ = self.data_socket.accept()
        result_messages = [result, data_conn.recv(1024).decode(), self.control_socket.recv(1024).decode()]

        data_conn.close()
        self.data_socket.close()
        return '\n'.join(result_messages)

    def retrieve_file(self, filepath: str) -> None:
        self.setup_data_connection()
        result = self.send_command(f"RETR {filepath}")
        print(result)

        if not result.startswith("150"):
            return

        os.makedirs("Downloads", exist_ok=True)
        data_conn, _ = self.data_socket.accept()

        try:
            with open(f"Downloads/{os.path.basename(filepath)}", 'wb') as f:
                while True:
                    data = data_conn.recv(1024)
                    if not data:
                        break
                    f.write(data)
            print(self.control_socket.recv(1024).decode())
        except Exception as e:
            print(f"Error: {e}")
        finally:
            data_conn.close()
            self.data_socket.close()

    def store_file(self, local_filepath: str, server_filepath: str) -> None:
        if not os.path.isfile(local_filepath):
            print(f"Error: File not found: {local_filepath}")
            return

        self.setup_data_connection()

        if not server_filepath.endswith('/') and not server_filepath.endswith('\\'):
            server_filepath += '/'

        server_filepath = os.path.join(server_filepath, os.path.basename(local_filepath)).replace("\\", "/")
        result = self.send_command(f"STOR {server_filepath}")
        print(result)

        if not result.startswith("150"):
            return

        data_conn, _ = self.data_socket.accept()

        try:
            with open(local_filepath, 'rb') as f:
                while chunk := f.read(1024):
                    data_conn.send(chunk)
            data_conn.close()
            print(self.control_socket.recv(1024).decode())
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.data_socket.close()

    def quit(self) -> str:
        self.control_socket.send("QUIT\r\n".encode())
        result_msg = self.control_socket.recv(1024).decode()
        self.control_socket.close()
        return result_msg


def main():
    try:
        # server_ip_adr = sys.argv[1]
        server_ip_adr = "127.0.0.1"  #for debugging purpose
    except IndexError:
        print("Please provide server IP address")
        return

    client = FTPClient(server_ip_adr, 2020)
    print(client.connect())

    while True:
        input_ = input("ftp> ").strip()
        command = input_.split(' ', 1)[0].upper()

        if command in ["USER", "PASS", "DELE", "MKD", "RMD", "PWD", "CWD", "CDUP"]:
            print(client.send_command(input_))

        elif command == "LIST":
            print(client.list_files(input_))

        elif command == "RETR":
            try:
                filename = input_.split(' ', 1)[1]
                client.retrieve_file(filename)
            except IndexError:
                print("Usage: RETR <filename>")

        elif command == "STOR":
            try:
                args = input_.split(' ', 2)[1:]
                if len(args) != 2:
                    raise ValueError
                local_filepath, server_filepath = args
                client.store_file(local_filepath, server_filepath)
            except ValueError:
                print("Usage: STOR <local_filepath> <server_filepath>")

        elif command == "QUIT":
            print(client.quit())
            break

        else:
            print(f"502 Command not implemented: {command}")


if __name__ == "__main__":
    main()
