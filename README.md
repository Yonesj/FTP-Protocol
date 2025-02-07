# **FTP Protocol Implementation**
This project is an implementation of the **File Transfer Protocol (FTP)**. FTP is a network protocol designed for transferring files between systems over the Internet. It enables users to upload and download files to/from a remote server efficiently.

<br>

## **Features**
- **SSL Encryption** – All sockets are wrapped in SSL for secure communication.  
- **Per-User File Access Control** – Each file is owned by a user and can only be modified or deleted by its owner. Others can have read access only if the owner specifies it when using the STOR command.  
- **Admin Role** – An admin user has full read, write, and delete permissions for all files.  
- **Django ORM Integration** – User data and file metadata are stored in a database using Django ORM.  
- **Secure Paths** – The server ensures that no user can access files outside the `server_storage` path. prevents directory traversal attacks by normalizing and validating the path.
- **Exception Handling**  
  - Invalid credentials return an authentication error.  
  - Non-existent files or directories return appropriate error codes.  
  - Permission errors are handled to restrict unauthorized operations.  

<br>

## **Implemented FTP Commands**
1. **USER** – Sends the username to the server for authentication.  
   ```
   USER <username>
   ```  
2. **PASS** – Sends the password to verify the user’s credentials.  
   ```
   PASS <password>
   ```  
3. **SIGNUP** – Registers a new user.  
   ```
   SIGNUP <username> <password>
   ```  
4. **QUIT** – Terminates the connection with the FTP server.  
   ```
   QUIT
   ```  
5. **LIST** – Lists the files and directories in the specified directory (or current directory if none is specified).  
   ```
   LIST [directory]
   ```  
6. **MODE** – Specifies data connection mode of client.  
   ```
   MODE [PASV|PORT]
   ```
7. **RETR** – Downloads a file from the server.  
   ```
   RETR <filename>
   ```  
8. **STOR** – Uploads a file to the server with specific access permissions.  
   ```
   STOR <client-file-path> <server-file-path> <visibility>
   ```  
9. **DELE** – Deletes a specified file on the server (only by the owner or admin).  
   ```
   DELE <filename>
   ```  
10. **MKD** – Creates a new directory on the server.  
   ```
   MKD <directory-name>
   ```  
11. **RMD** – Removes a directory from the server.  
   ```
   RMD <directory-name>
   ```  
12. **PWD** – Displays the current working directory on the server.  
   ```
   PWD
   ```  
13. **CWD** – Changes the working directory on the server.  
   ```
   CWD <directory-path>
   ```  
14. **CDUP** – Moves up to the parent directory.  
   ```
   CDUP
   ```  

<br>

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

