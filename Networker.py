import http.client
import json

from coapthon.client.helperclient import HelperClient
from coapthon import defines
from coapthon.messages.message import Message
from coapthon.messages.request import Request

from Crypto.Cipher import AES
import hashlib
import pyotp

import socket
import time
import datetime
import binascii
import os

#DTLS
import ssl
from dtls.wrapper import wrap_client

class Networker:

	groupNonce = "Null"
	database = {}
	CA_CERT = "clientCert.pem"

	def __init__(self):
		with open("db", "r") as f:
			data = f.readlines()
		
		for line in data:
			if line[:1] == "!":
				self.groupNonce = line[1:-1]
			else:
				info = line.split(":")
				self.database[info[0]] = info[1][:-1]

	##DTLS Funcs
	def _cb_ignore_read_exception(self, exception, client):
		return False

	def _cb_ignore_write_exception(self, exception, client):
		return False


	def test(self, token):
                conn = http.client.HTTPSConnection('172.0.17.2', 9443)
                header = {'Authorization' : 'Basic YWRtaW46YWRtaW4=', 'Content-Type' : 'application/x-www-form-urlencoded;charset=UTF-8'}
                body = 'token=' + token.split(' ')[1]
                conn.request('POST', '/oauth2/introspect', body, header)
                response = conn.getresponse()
                jsonResponse = json.loads(response.read().decode("utf-8"))
                if jsonResponse.get('active') == True:
                        return True
                else:
                        return False

	def req(self, request):
		hotp = pyotp.HOTP(self.groupNonce)
		
		now = time.time()
		timeCode = int(datetime.datetime.fromtimestamp(now).strftime('%Y%m%d%H%M%S'))
		timeStamp = datetime.datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')

		groupKey = hotp.at(timeCode)
		m = hashlib.md5()
		m.update(groupKey.encode("UTF-8"))
		hashedKey = m.hexdigest()[:16]

		IV = os.urandom(16)
		encryptor = AES.new(hashedKey, AES.MODE_CBC, IV=IV)
		length = 16 - (len(request) % 16)
		data = bytes([length])*length
		request += data.decode("utf-8")
		cipherText = encryptor.encrypt(request)
		return self.send(binascii.hexlify(cipherText).upper(), timeStamp, binascii.hexlify(IV).upper())

	def send(self, data, timestamp, iv):
		#Set up client DTLS socket
		cipher = "ALL"
		cipher = str(cipher.encode('ascii'))
		print(cipher)
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock = wrap_client(sock,
				cert_reqs=ssl.CERT_REQUIRED,
				ca_certs=self.CA_CERT,
				ciphers=cipher,
				do_handshake_on_connect=False)

		client = HelperClient(server=("224.0.1.187", 5001),
				sock=sock,
				cb_ignore_read_exception=self._cb_ignore_read_exception,
				cb_ignore_write_exception=self._cb_ignore_write_exception)
		
		#Setup request and content
		dict = { "data" : str(data)[2:-1], "timestamp": timestamp, "iv": str(iv)[2:-1] }
		jsonStr = json.dumps(dict)
	
		request = Request()
		request.destination = client.server
		request.code = defines.Codes.GET.number
		request.uri_path = 'info/'
		request.payload = jsonStr

		client.send_request(request)
		client.stop()

		return "Sended"


print(Networker().req("infox"))
