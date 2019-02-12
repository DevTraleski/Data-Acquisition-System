import http.client
import json

from coapthon.client.helperclient import HelperClient
from coapthon import defines
from coapthon.messages.message import Message
from coapthon.messages.request import Request

from Crypto.Cipher import AES
import hashlib
import pyotp

import time
import datetime
import binascii
import os

class Networker:

	groupNonce = "Null"
	database = {}

	def __init__(self):
		with open("db", "r") as f:
			data = f.readlines()
		
		for line in data:
			if line[:1] == "!":
				self.groupNonce = line[1:-1]
			else:
				info = line.split(":")
				self.database[info[0]] = info[1][:-1]

	def test(self, token):
                print(token)
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
		print("Time Code: " + str(timeCode))

		groupKey = hotp.at(timeCode)
		m = hashlib.md5()
		m.update(groupKey.encode("UTF-8"))
		hashedKey = m.hexdigest()[:16]
		print("Group Key: " + str(groupKey))
		print("Hashed Key: " + str(hashedKey))

		IV = os.urandom(16)
		print("Original IV: " + str(IV))
		encryptor = AES.new(hashedKey, AES.MODE_CBC, IV=IV)
		length = 16 - (len(request) % 16)
		data = bytes([length])*length
		request += data.decode("utf-8")
		print("Request with padding: " + request)
		cipherText = encryptor.encrypt(request)
		print("Original Data: " + str(cipherText))
		return self.send(binascii.hexlify(cipherText).upper(), timeStamp, binascii.hexlify(IV).upper())

	def send(self, data, timestamp, iv):
		print("Hexed Data: " + str(data))
		print("Hexed IV: " + str(iv))
		client = HelperClient(server=("224.0.1.187", 5001))
		
		dict = { "data" : str(data)[2:-1], "timestamp": timestamp, "iv": str(iv)[2:-1] }
		jsonStr = json.dumps(dict)
		print(jsonStr)	
	
		request = Request()
		request.destination = client.server
		request.code = defines.Codes.GET.number
		request.uri_path = 'info/'
		request.payload = jsonStr

		response = client.send_request(request)
		client.stop()

		print("Response: " + response.pretty_print())
		return response.payload
		
		

print(Networker().req("infox"))

#decipher = AES.new(hashedKey, AES.MODE_CBC, IV)
#plainText = decipher.decrypt(cipherText)
#print(plainText)
