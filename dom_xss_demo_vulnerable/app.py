# FILE: dom_xss_demo/app.py
# ISEC3004 Assignment 1 — Vulnerability 1: DOM-based Cross-Site Scripting
# Member 1 — Vulnerable Application
#
# WHAT THIS FILE DOES:
# Serves a university notice-board web application called CurtiBoard.
# The app has a search feature that passes the user's query through the
# URL fragment (location.hash). This fragment is then read by client-side
# JavaScript in static/js/board.js and written into the page using innerHTML.
#
# WHY THIS IS DOM-BASED XSS (not reflected or stored):
# The server NEVER reads, processes, or echoes back the search query.
# Look at the /board route below — it calls render_template() with no
# user-supplied arguments at all. The Flask access log will show only:
#   GET /board HTTP/1.1
# with zero trace of any payload, because browsers strip the URL fragment
# before sending the HTTP request. The entire attack happens inside the
# victim's browser — that client-side, server-invisible nature is the
# defining characteristic of DOM-based XSS.
#
# VULNERABILITY LOCATION:
#   Source : location.hash   in static/js/board.js
#   Sink   : innerHTML       in static/js/board.js
#   No server-side code is involved in the vulnerability at all.

from flask import Flask, render_template, make_response

app = Flask(__name__)

# NOTE: No Content-Security-Policy header is set in this vulnerable version.
# The absence of CSP means the browser applies no restriction on script
# execution, so any JavaScript injected via the innerHTML sink runs freely.
# Member 2 will add the CSP header as a defence-in-depth mitigation.


@app.route("/")
def index():
    from flask import redirect, url_for
    return redirect(url_for("board"))


@app.route("/board")
def board():
    """
    VULNERABLE ROUTE — serves the notice board page.

    SERVER-SIDE PROOF OF DOM-BASED XSS:
    This route accepts no query parameters and reads no user input whatsoever.
    render_template() is called with only a static template name. Whatever
    the attacker puts after '#' in the URL is never received by this function.
    It is confirmed by: run the app, open the Flask terminal, and paste the exploit
    URL into the browser. The terminal will show:
        127.0.0.1 - - [date] "GET /board HTTP/1.1" 200 -
    The payload is completely absent from the server log.
    """
    resp = make_response(render_template("board.html"))

    # Demo cookies — deliberately set with httponly=False so they are
    # readable by document.cookie in the browser. In a real application
    # both of these would be set HttpOnly to prevent JavaScript access.
    # Leaving them accessible here makes the XSS impact concrete: when
    # Member 2 runs the exploit, document.cookie reveals these values,
    # demonstrating that a real attacker could exfiltrate a live session token.
    resp.set_cookie("session_id",  "curtiboard-sess-abc123", httponly=False)
    resp.set_cookie("user_role",   "student",                httponly=False)

    return resp


@app.route("/notice/<int:notice_id>")
def notice_detail(notice_id):
    """Individual notice detail page — no user input processed here either."""
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
         "body": "Building 314 Wi-Fi offline Saturday 4 Oct, 08:00-12:00."},
        {"id": 4, "title": "Cyber Club CTF Meeting",
         "category": "Events",
         "body": "Weekly Cyber Club meeting Thursday, Room 215, 5pm. CTF warm-up session."},
        {"id": 5, "title": "Lecture Slides Updated",
         "category": "Security",
         "body": "Week 7 Path Traversal slides updated on Blackboard."},
    ]


if __name__ == "__main__":
    print("\n  [VULNERABLE MODE] CurtiBoard starting.")
    print("  Visit: http://127.0.0.1:5000/board")
    print("  No CSP header — innerHTML sink is fully exploitable.\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
