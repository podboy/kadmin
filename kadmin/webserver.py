# coding:utf-8

from functools import wraps
from os.path import dirname
from typing import Optional

from flask import Flask
from flask import Response
from flask import redirect
from flask import render_template
from flask import request
from xhtml.locale.template import LocaleTemplate
from xkits_key import SSHKeys
from xpw import AuthInit
from xpw import SessionKeys
from xpw import TokenAuth

from kadmin.attribute import __project__
from kadmin.attribute import __urlhome__
from kadmin.attribute import __version__


def init(locale: LocaleTemplate, session_keys: SessionKeys, authentication: TokenAuth, ssh_keys: SSHKeys) -> Flask:  # noqa:E501
    app: Flask = Flask(__name__)

    def passthrough(fn):
        @wraps(fn)
        def decorated_function(*args, **kwargs):
            session_id = request.cookies.get("session_id")
            if not session_id or not session_keys.verify(session_id):
                return redirect("/login")
            return fn(*args, **kwargs)
        return decorated_function

    @app.route("/logout/", methods=["GET", "POST"])
    def logout():
        if session_id := request.cookies.get("session_id"):
            session_keys.sign_out(session_id)
        return redirect("/")

    @app.route("/login/", methods=["GET"])
    def get_login():
        if (session_id := request.cookies.get("session_id")) and session_keys.verify(session_id):  # noqa:E501
            return redirect("/")
        textdata = render_template("login.html", **locale.search(request.accept_languages.to_header(), "login").fill())  # noqa:E501
        response: Response = Response(textdata, status=200, mimetype="text/html")  # noqa:E501
        if not session_id:
            response.set_cookie("session_id", session_keys.search().name)
        return response

    @app.route("/login/", methods=["POST"])
    def post_login():
        input_error_prompt: str = ""
        session_id = request.cookies.get("session_id")
        username: str = request.form.get("username", "")
        password: str = request.form.get("password", "")
        section = locale.search(request.accept_languages.to_header(), "login")
        if not password:
            input_error_prompt = section.get("input_password_is_null")
        elif session_id and authentication.verify(username, password):
            session_keys.sign_in(session_id)
            return redirect("/")
        else:
            input_error_prompt = section.get("input_verify_error")
        context = section.fill()
        context.setdefault("input_error_prompt", input_error_prompt)
        return render_template("login.html", **context)

    @app.route("/create/", methods=["GET"])
    @passthrough
    def get_create():
        context = locale.search(request.accept_languages.to_header(), "create").fill()  # noqa:E501
        return render_template("create.html", **context, project=__project__,
                               urlhome=__urlhome__, version=__version__)

    @app.route("/create/", methods=["POST"])
    @passthrough
    def post_create():
        try:
            keyname: str = request.form["keyname"]
            private: str = request.form["private"]
            print(private)
            name: str = ssh_keys.create(name=keyname, private=private)
            return redirect(f"/overview/{name}")
        except Exception:
            return redirect("/")

    @app.route("/generate/", methods=["GET"])
    @passthrough
    def get_generate():
        context = locale.search(request.accept_languages.to_header(), "generate").fill()  # noqa:E501
        return render_template("generate.html", **context, project=__project__,
                               urlhome=__urlhome__, version=__version__)

    @app.route("/generate/", methods=["POST"])
    @passthrough
    def post_generate():
        try:
            keytype: str = request.form["keytype"]
            keyname: str = request.form["keyname"]
            comment: str = request.form["comment"]
            name: str = ssh_keys.generate(type=keytype, name=keyname, comment=comment)  # noqa:E501
            return redirect(f"/overview/{name}")
        except Exception:
            return redirect("/")

    @app.route("/overview/", defaults={"path": "/"}, methods=["GET"])
    @app.route("/overview/<path:path>", methods=["GET"])
    @passthrough
    def overview(path: str):
        context = locale.search(request.accept_languages.to_header(), "overview").fill()  # noqa:E501
        return render_template("overview.html", **context, project=__project__,
                               urlhome=__urlhome__, version=__version__)

    @app.route("/dashboard/", methods=["GET"])
    @passthrough
    def dashboard():
        context = locale.search(request.accept_languages.to_header(), "dashboard").fill()  # noqa:E501
        return render_template("dashboard.html", **context, project=__project__,  # noqa:E501
                               urlhome=__urlhome__, version=__version__)

    @app.route("/profile/", methods=["GET"])
    @passthrough
    def profile():
        context = locale.search(request.accept_languages.to_header(), "profile").fill()  # noqa:E501
        return render_template("profile.html", **context, project=__project__,
                               urlhome=__urlhome__, version=__version__)

    @app.route("/", methods=["GET"])
    @passthrough
    def index():
        return redirect("/dashboard")

    return app


def run(host: str = "0.0.0.0", port: int = 5000, debug: bool = True,
        auth: Optional[TokenAuth] = None):
    locale: LocaleTemplate = LocaleTemplate(dirname(__file__))

    app = init(locale=locale, session_keys=SessionKeys(),
               authentication=auth or AuthInit.from_file(),
               ssh_keys=SSHKeys())
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run()
