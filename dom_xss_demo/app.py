# FILE: dom_xss_demo/app.py
# ISEC3004 Assignment 1 - Vulnerability 1: DOM-based Cross-Site Scripting
#
# REASONING: This route deliberately serves a page whose CLIENT-SIDE
# JavaScript is unsafe. Flask itself never receives or reflects any
# attacker-controlled input for this vulnerability;the server only
# renders a static template. The vulnerability lives entirely inside
# welcome.html's <script> block (see below), which is what makes this
# DOM-based XSS rather than reflected/stored XSS.
 
from flask import Flask, render_template
 
app = Flask(__name__)

@app.after_request
def set_security_headers(response):
    # Defence-in-depth: add a strict Content-Security-Policy.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'"
    )
    return response
 
 
@app.route("/welcome")
def welcome():
    # No user input is read or templated on the server side here.
    return render_template("welcome.html")
 
 
if __name__ == "__main__":
    # Bind to localhost only - this app must never be exposed outside
    # your own machine.
    app.run(host="127.0.0.1", port=5000, debug=True)
