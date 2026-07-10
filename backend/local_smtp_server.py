import socket
import ssl
import sys
import threading
import time

def handle_client(client_socket):
    try:
        # Send greeting
        client_socket.sendall(b"220 localhost SMTP UTF8HOST Ready\r\n")
        
        tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        
        # Disable cert validation checks on client connection if needed, though client doesn't check server cert unless requested
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE
        
        secure_socket = client_socket
        is_tls = False
        
        while True:
            data = secure_socket.recv(4096)
            if not data:
                break
            
            line = data.decode("utf-8", errors="ignore").strip()
            print(f"SMTP Server Received: {line}", flush=True)
            
            if line.upper().startswith("EHLO") or line.upper().startswith("HELO"):
                if not is_tls:
                    secure_socket.sendall(b"250-localhost\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n")
                else:
                    secure_socket.sendall(b"250-localhost\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n")
            elif line.upper().startswith("STARTTLS"):
                secure_socket.sendall(b"220 Ready to start TLS\r\n")
                try:
                    # Wrap socket in TLS
                    secure_socket = tls_context.wrap_socket(secure_socket, server_side=True)
                    is_tls = True
                except Exception as tls_err:
                    print(f"TLS wrapping error: {tls_err}", flush=True)
                    break
            elif line.upper().startswith("AUTH"):
                # Handle AUTH LOGIN/PLAIN
                if "login" in line.lower():
                    secure_socket.sendall(b"334 VXNlcm5hbWU6\r\n") # base64 for "Username:"
                    user_data = secure_socket.recv(4096).decode("utf-8", errors="ignore").strip()
                    secure_socket.sendall(b"334 UGFzc3dvcmQ6\r\n") # base64 for "Password:"
                    pass_data = secure_socket.recv(4096).decode("utf-8", errors="ignore").strip()
                    secure_socket.sendall(b"235 Authentication successful\r\n")
                else:
                    secure_socket.sendall(b"235 Authentication successful\r\n")
            elif line.upper().startswith("MAIL FROM:"):
                secure_socket.sendall(b"250 OK\r\n")
            elif line.upper().startswith("RCPT TO:"):
                secure_socket.sendall(b"250 OK\r\n")
            elif line.upper().startswith("DATA"):
                secure_socket.sendall(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                mail_data = b""
                while True:
                    chunk = secure_socket.recv(4096)
                    mail_data += chunk
                    if b"\r\n.\r\n" in mail_data or mail_data.endswith(b"\n.\n") or mail_data.endswith(b"\n.\r\n"):
                        break
                print(f"SMTP Server Received Mail Body:\n{mail_data.decode('utf-8', errors='ignore')}", flush=True)
                with open("received_emails.log", "a", encoding="utf-8") as f:
                    f.write(f"--- EMAIL RECEIVED AT {time.ctime()} ---\n")
                    f.write(mail_data.decode('utf-8', errors='ignore'))
                    f.write("\n=====================================\n")
                secure_socket.sendall(b"250 OK Message accepted for delivery\r\n")
            elif line.upper().startswith("QUIT"):
                secure_socket.sendall(b"221 localhost Service closing transmission channel\r\n")
                break
            else:
                secure_socket.sendall(b"500 Command unrecognized\r\n")
    except Exception as e:
        print(f"Error handling client: {e}", flush=True)
    finally:
        try:
            client_socket.close()
        except:
            pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 1025))
    server.listen(5)
    print("Mock SMTP Server listening on 127.0.0.1:1025...", flush=True)
    
    while True:
        try:
            client_socket, addr = server.accept()
            print(f"Accepted connection from {addr}", flush=True)
            t = threading.Thread(target=handle_client, args=(client_socket,))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Server error: {e}", flush=True)

if __name__ == "__main__":
    main()
