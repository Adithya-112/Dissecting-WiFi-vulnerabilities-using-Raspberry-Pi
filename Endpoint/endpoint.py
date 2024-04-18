import socket
import os
import requests

HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 8080

DISCORD_WEBHOOK_URL = "" #change this with your webhook url
# create a hc22000 directory before running

def send_discord_message(message):
    payload = {'content': message}
    response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
    print(f"Response status code: {response.status_code}")
    print(f"Response content: {response.content}")
    if response.status_code == 204:
        print("Discord message sent successfully")
    elif response.status_code != 200:
        print(f"Failed to send Discord message. Status code: {response.status_code}")



def save_file(filename, data):
    with open(os.path.join("hc22000", filename), 'wb') as f:
        f.write(data)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            print(f"Connection from {addr}")

            with conn:
                # Receive filename
                filename = b''
                while True:
                    chunk = conn.recv(1)
                    if chunk == b'\r':
                        break
                    filename += chunk
                filename = filename.decode()
                print(f"Receiving file: {filename}")

                # Consume newline character
                conn.recv(1)

                # Receive file contents
                data = b''
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk

                # Save file
                save_file(filename, data)
                print(f"File saved as: {filename}")

                # Send message to Discord webhook
                send_discord_message(f"File `{filename}` has been received and saved in the 'hc22000' directory.")


if __name__ == "__main__":
    main()
