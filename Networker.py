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
import _thread

class Networker:

	groupNonce = "Null"
	database = {}

	expected = 0
	received = 0
	responses = {}
	
	timeOutStamp = "Null"

	def __init__(self):
		self.loadDB()		

	def loadDB(self):
		with open("db", "r") as f:
			data = f.readlines()

		for line in data:
			if line[:1] == "!":
				self.groupNonce = line[1:-1]
			else:
				info = line.split(":")
				self.database[info[0]] = info[1][:-1]
		self.expected = len(self.database)
		f.close()
		

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
		client = HelperClient(server=("224.0.1.187", 5001))
		
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
		
		self.timeOutStamp = time.time()
		_thread.start_new_thread(self.checkIfShouldSend, ())

		return "Sended"

	def _decrypt(self, request):
		jsonStr = request.payload
		dict = json.loads(jsonStr)

		decipher = AES.new(self.database[dict['serial']], AES.MODE_CBC, binascii.unhexlify(dict['iv']))
		unhexData = binascii.unhexlify(dict['data'])
		plainText = decipher.decrypt(unhexData)
		plainText = plainText[:-plainText[-1]]

		#Value, encrypt, json, return
		return plainText.decode("utf-8")



	def respond(self, request):
		self.timeOutStamp = time.time()

		data = self._decrypt(request)
		dict = json.loads(data)
		
		data = dict['data']
		timestamp = dict['timestamp']
		iv = dict['iv']
		serial = dict['serial']

		dados = { 'data' : data,
			'timestamp' : timestamp,
			'iv' : iv,
			'serial' : serial }
		payload = json.dumps(dados)
		self.responses[serial] = payload		
		self.received = len(self.responses)
		
		return "OK"

	def sendAlert(self, request):
		payload = self._decrypt(request)
		connection = http.client.HTTPSConnection('172.0.17.4', 5000)
		header = {'Content-Type' : 'application/x-www-form-urlencoded;charset=UTF-8'}
		body = 'alert=' + payload + '&gateway=gateway_a'
		connection.request('POST', '/alert', body, header)
		response = connection.getresponse()

	def checkIfShouldSend(self):
		if(self.received == self.expected or (time.time() - self.timeOutStamp) > 5):
			self.forward()
		else:
			time.sleep(2)
			self.checkIfShouldSend()

	def forward(self):
		print("Expected: " + str(self.expected) + "\nReceived: " + str(self.received))
		if(self.received) > 0:
			connection = http.client.HTTPSConnection('172.0.17.4', 5000)
			header = {'Content-Type' : 'application/x-www-form-urlencoded;charset=UTF-8'}
			body = 'res=' + json.dumps(self.responses)
			connection.request('GET', '/response', body, header)
			response = connection.getresponse()
		else:
			print('Nobody replied, try again?')

	def setup(self, request):
		serial = request.payload
		
		if serial in self.database.keys():
			print("Serial already registered")
			return '{"error":"Serial already registered"}'
		else:
			dtlsk = str(binascii.hexlify(os.urandom(16)).upper())[2:-1]

			connection = http.client.HTTPSConnection('172.0.17.4', 5000)
			header = {'Content-Type' : 'application/x-www-form-urlencoded;charset=UTF-8'}
			body = 'gnonce=' + self.groupNonce + '&dtlsk=' + dtlsk + '&gateway=gateway_a&serial=' + serial
			connection.request('GET', '/setup', body, header)
			response = connection.getresponse()
		
			payload = response.read().decode('utf-8')

			dict = json.loads(payload)
			if 'error' in dict.keys():
				return payload
			else:
				db = open("db", "a")
				db.write(serial + ":" + dtlsk + "\n")
				db.close()

				self.loadDB()
				return payload
		

#print(Networker().req("infox"))
