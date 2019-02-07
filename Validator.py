import http.client
import json

class Validator:

	def __init__(self):
		print("Created")

	def test(self, token):
		print(token)
		conn = http.client.HTTPSConnection('172.17.0.2', 9443)
		header = {'Authorization' : 'Basic YWRtaW46YWRtaW4=', 'Content-Type' : 'application/x-www-form-urlencoded;charset=UTF-8'}
		body = 'token=' + token
		conn.request('POST', '/oauth2/introspect', body, header)
		response = conn.getresponse()
		jsonResponse = json.loads(response.read().decode("utf-8"))
		if jsonResponse.get('active') == True:
			return True
		else:
			return False

#Validator().test("9a422138-6877-3871-a756-2363b650bbb1")
