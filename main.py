from flask import Flask, jsonify, request

app = Flask(__name__)
app.config.update(
    DEBUG=True,
    JSONIFY_PRETTYPRINT_REGULAR=True,
    JSON_SORT_KEYS=False,
    JSON_AS_ASCII=False
)

@app.route("/", methods=["GET"])
def base():
    return jsonify(message="hi")


# errors !
@app.errorhandler(400)
def bad_request(e):
    return jsonify(error="Bad Request", status=400, message=str(e)), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify(error="Unauthorized", status=401, message=str(e)), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify(error="Forbidden", status=403, message=str(e)), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify(error="Not Found", status=404, message=str(e)), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify(error="Internal Server Error", status=500, message=str(e)), 500

if __name__ == "__main__":
    app.run()
