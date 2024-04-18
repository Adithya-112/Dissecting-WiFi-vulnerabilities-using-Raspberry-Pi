After downloading this repository:

First create a directory named "endpoint"

In that directory paste these 5 files ( endpoint.py, endpoint_run.bat, hashcat_handler.py, hashcat_handler_run.bat, requirements.txt)

Create another directory "hc22000" inside the endpoint directory

Download "Hashcat" and extract it in the enpoint directory

And if you've downloaded any "Wordlists" like in this code we've used indian-passwords.txt and rockyou.txt, then paste them inside the hashcat directory (The hashcat directory will look something like this: hashcat-6.2.6)

Then install the requirements ( pip install -r requirements.txt)

Then run both the files i.e. endpoint_run.bat & hashcat_handler_run.bat and then from Raspberry Pi you can start running 'main.py'
