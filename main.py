from coapthon.resources.resource import Resource
from coapthon.server.coap import CoAP
from Networker import Networker
from flask import Flask, request
import _thread
import time
import logging
from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'ERROR',
        'handlers': ['wsgi']
    }
})

app = Flask("Gateway")

networker = Networker()

@app.route("/reload")
def reload():
	return networker.reload()

@app.route("/search")
def search():
	token = request.headers.get('Authorization')
	req = request.form.get('req')

	if networker.test(token) == False:
		return "Token expired or invalid"
	return networker.req(req)

class Setup(Resource):
	def __init__(self, name="Setup", coap_server=None):
		super(Setup, self).__init__(name, coap_server, visible=True, observable=True, allow_children=True)

	def render_GET(self, request):
		print("Setup called")
		self.payload = networker.setup(request)
		return self

class Alert(Resource):
	def __init__(self, name="Alert", coap_server=None):
		super(Alert, self).__init__(name, coap_server, visible=True, observable=True, allow_children=True)

	def render_POST(self, request):
		networker.sendAlert(request)
		return self

class Respond(Resource):
	def __init__(self, name="Respond", coap_server=None):
		super(Respond, self).__init__(name, coap_server, visible=True, observable=True, allow_children=True)
		
	def render_POST(self, request):
		networker.respond(request)
		return self

class CoAPServer(CoAP):
	def __init__(self, host, port):
		CoAP.__init__(self, (host, port))
		self.add_resource('respond/', Respond())
		self.add_resource('setup/', Setup())
		self.add_resource('alert/', Alert())

def runCoap():
	server = CoAPServer("0.0.0.0", 1337)
	try:
		server.listen(10)
	except KeyboardInterrupt:
		print ("Server Shutdown")
		server.close()
		print("Exiting...")

def runRest():
	app.run(ssl_context=('cert.pem', 'key.pem'), host="0.0.0.0", port="4000")

def main():
	_thread.start_new_thread(runCoap, ())
	runRest()


if __name__ == "__main__":
	main()
