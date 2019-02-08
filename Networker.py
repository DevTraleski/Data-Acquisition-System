import http.client
import json

from coapthon.client.helperclient import HelperClient

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
		body = 'token=' + token
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
		timeCode = int(datetime.datetime.fromtimestamp(now).strftime('%Y%H%M'))
		timeStamp = datetime.datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')

		groupKey = hotp.at(timeCode)
		m = hashlib.md5()
		m.update(groupKey.encode("UTF-8"))
		hashedKey = m.hexdigest()

		IV = os.urandom(16)
		encryptor = AES.new(hashedKey, AES.MODE_CBC, IV=IV)
		cipherText = encryptor.encrypt(request)
		return binascii.hexlify(cipherText).upper()

		#decipher = AES.new(hashedKey, AES.MODE_CBC, IV)
		#plainText = decipher.decrypt(cipherText)
		#print(plainText)
		

#Networker().req("Search0000000000")
