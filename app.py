from flask import Flask, render_template, request, jsonify
from scanner import scan_website

app = Flask(__name__)

# ----------------------------------
# HOME PAGE
# ----------------------------------

@app.route("/")
def home():

    return render_template("index.html")

# ----------------------------------
# SCAN ENDPOINT
# ----------------------------------

@app.route("/scan", methods=["POST"])
def scan():

    try:

        data = request.get_json()

        url = data.get("url")

        if not url:

            return jsonify({
                "error": "URL is required"
            })

        results = scan_website(url)

        return jsonify(results)

    except Exception as e:

        return jsonify({
            "error": str(e)
        })

# ----------------------------------
# MAIN
# ----------------------------------

if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )