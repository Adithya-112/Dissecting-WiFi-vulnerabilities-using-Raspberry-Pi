# Run this code inside Raspberry Pi
Here for the raspyberry pi, I have installed the default Raspberry Pi OS in my Raspberry Pi.

You will need a WiFi adapter which supports "Monitor Mode" or more specifically "Promiscuous Mode" in order to run this code.

Then after give root permissions to the 'main.py' file ( $ sudo chown root main.py)

Then give the permissions to 'main.py' file ( $ sudo chmod 777 main.py)

See that python is there, if not then install the python
Then install the 'requirments.txt' file ( $ sudo pip install -r requirements.txt) - this will install all modules required

Then open the main.py file and perform the changes that are mentioned in the comments ( $ sudo nano main.py)

Finally, after performing all the required arrangements, to run the code: "$ sudo python main.py wlan1 "( here wlan1 is my wifi adapter name, change it with yours)
To check the wifi adpater: $ sudo iwconfig
