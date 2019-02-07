import http.client
import json

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

Networker().test("toke")
