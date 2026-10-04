from flask import Flask, render_template, request, redirect, url_for, session, abort
from pathlib import Path
from datetime import datetime

app = Flask(__name__)
app.secret_key = "group8-path-traversal-demo-key"

BASE_DIR = Path(__file__).resolve().parent
DOCUMENTS_DIR = BASE_DIR / "documents"
LOG_FILE = BASE_DIR / "logs" / "access.log"


def log_access(username, requested_file, status):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(
            f"{timestamp} | user={username} | "
            f"requested={requested_file} | status={status}\n"
        )


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()

        if username:
            session["username"] = username
            return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


@app.route("/documents")
def documents():
    if "username" not in session:
        return redirect(url_for("login"))

    files = sorted(
        file.name
        for file in DOCUMENTS_DIR.iterdir()
        if file.is_file() and file.suffix == ".txt"
    )

    return render_template(
        "documents.html",
        username=session["username"],
        files=files
    )


@app.route("/documents/<path:filename>")
def view_document(filename):
    if "username" not in session:
        return redirect(url_for("login"))

    requested_path = DOCUMENTS_DIR / filename

    try:
        with open(requested_path, "r", encoding="utf-8") as document:
            content = document.read()

        log_access(session["username"], filename, "ALLOWED")
        return render_template(
            "document_view.html",
            username=session["username"],
            filename=filename,
            content=content
        )

    except (FileNotFoundError, IsADirectoryError, UnicodeDecodeError):
        log_access(session["username"], filename, "NOT_FOUND")
        abort(404)

@app.route("/view")
def view_by_parameter():
    if "username" not in session:
        return redirect(url_for("login"))

    filename = request.args.get("file", "")

    if not filename:
        abort(400)

    requested_path = (DOCUMENTS_DIR / filename).resolve()
    documents_root = DOCUMENTS_DIR.resolve()

    try:
        requested_path.relative_to(documents_root)
    except ValueError:
        log_access(session["username"], filename, "BLOCKED_TRAVERSAL")
        abort(403)

    try:
        with open(requested_path, "r", encoding="utf-8") as document:
            content = document.read()

        log_access(session["username"], filename, "ALLOWED")
        return render_template(
            "document_view.html",
            username=session["username"],
            filename=filename,
            content=content
        )

    except (FileNotFoundError, IsADirectoryError, UnicodeDecodeError):
        log_access(session["username"], filename, "NOT_FOUND")
        abort(404)

if __name__ == "__main__":
    app.run(debug=True)
