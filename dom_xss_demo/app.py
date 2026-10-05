# ISEC3004 Assignment 1 - DOM XSS
# Member 2 - Mitigated version

from flask import Flask, render_template, make_response

app = Flask(__name__)

# Set to True for the fixed version.
ENABLE_MITIGATIONS = True


@app.after_request
def apply_security_headers(response):
    # Add CSP as an extra layer of protection.
    if ENABLE_MITIGATIONS:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'"
        )
    return response


@app.route("/")
def index():
    from flask import redirect, url_for
    return redirect(url_for("board"))


@app.route("/board")
def board():
    # The XSS vulnerability is fixed in board.js.
    resp = make_response(render_template("board.html"))

    # Demo cookies used to demonstrate the XSS impact.
    resp.set_cookie("session_id", "curtiboard-sess-abc123", httponly=False)
    resp.set_cookie("user_role", "student", httponly=False)

    return resp


@app.route("/notice/<int:notice_id>")
def notice_detail(notice_id):
    notices = _notice_data()
    item = next((n for n in notices if n["id"] == notice_id), None)

    if not item:
        return "<h2>Notice not found</h2><a href='/board'>Back</a>", 404

    return render_template("notice.html", notice=item)


def _notice_data():
    return [
        {"id": 1, "title": "ISEC3004 Lab 9 Reminder",
         "category": "Security",
         "body": "Lab 9 covers Burp Suite proxy interception. Bring your laptops."},

        {"id": 2, "title": "Assignment 1 Submission Deadline",
         "category": "Assessment",
         "body": "Group Security Project due 9 October 2026 at 23:59 via Blackboard."},

        {"id": 3, "title": "Campus Wi-Fi Maintenance",
         "category": "IT",
         "body": "Building 314 Wi-Fi offline Saturday 4 Oct, 08:00–12:00."},

        {"id": 4, "title": "Cyber Club CTF Meeting",
         "category": "Events",
         "body": "Weekly Cyber Club meeting Thursday, Room 215, 5pm. CTF warm-up."},

        {"id": 5, "title": "Lecture Slides Updated",
         "category": "Security",
         "body": "Week 7 Path Traversal slides updated on Blackboard."},
    ]


if __name__ == "__main__":
    print("\n  [MITIGATED MODE] CurtiBoard starting.")
    print("  Visit: http://127.0.0.1:5000/board")
    print("  CSP header active. innerHTML sink replaced with textContent.\n")

    app.run(host="127.0.0.1", port=5000, debug=True)