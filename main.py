from flask import Flask, request, jsonify
from Networker import Networker

app = Flask(__name__)
app.config["SECRET_KEY"] = "9WjsiJ74/NcwpLm6MuCV9RLZygQh5V2v79Df8/QsaKQ="

networker = Networker()

@app.route("/search")
def search():
	token = request.headers.get('Authorization')
	req = request.form.get('req')

	if networker.test(token) == False:
		return "Token expired or invalid"
	return networker.req(req)

if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'), host="0.0.0.0", port="4000")
