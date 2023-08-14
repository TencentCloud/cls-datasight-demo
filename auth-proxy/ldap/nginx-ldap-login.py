#!/bin/sh
''''which python  >/dev/null && exec python  "$0" "$@" # '''

# Copyright (C) 2014-2015 Nginx, Inc.

# Example of an application working on port 9000
# To interact with nginx-ldap-auth-daemon this application
# 1) accepts GET  requests on /login and responds with a login form
# 2) accepts POST requests on /login, sets a cookie, and responds with redirect

# pylint: disable=invalid-name
import sys
import os
import signal
import base64
import cgi
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv()

if sys.version_info.major == 2:
    from urlparse import urlparse, parse_qs
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
elif sys.version_info.major == 3:
    from urllib.parse import urlparse, parse_qs
    from http.server import HTTPServer, BaseHTTPRequestHandler

Listen = ('0.0.0.0', 9000)

if sys.version_info.major == 2:
    from SocketServer import ThreadingMixIn
elif sys.version_info.major == 3:
    from socketserver import ThreadingMixIn


def ensure_bytes(data):
    return data if sys.version_info.major == 2 else data.encode("utf-8")


class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class AppHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        url = urlparse(self.path)

        if url.path.startswith("/login/assets"):
            if url.path.endswith(".js") or url.path.endswith(".css"):
                path_split = url.path.split("/")
                my_path = (os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
                           + "/login-page/assets/"
                           + path_split[len(path_split) - 1])
                html = open(my_path, "r").read()

                self.send_response(200)
                if url.path.endswith(".js"):
                    self.send_header("Content-type", "application/javascript")
                elif url.path.endswith(".css"):
                    self.send_header("Content-type", "text/css")
                self.send_header("Cache-Control", "max-age=86400")
                self.end_headers()
                self.wfile.write(ensure_bytes(html))
                return
            else:
                self.send_response(404)
                self.end_headers()
                return

        if url.path.startswith("/login"):
            return self.auth_form()

        self.send_response(200)
        self.end_headers()
        self.wfile.write(ensure_bytes('Hello, world! '))

    # send login form html
    def auth_form(self, target=None):

        # try to get target location from header
        if target is None:
            target = self.headers.get('X-Target')
        # redirect to s_url or homepage if target is login page
        if target.startswith('/login'):
            parse_target = urlparse(target)
            dict_target = parse_qs(parse_target.query)
            if 's_url' in dict_target and len(dict_target['s_url']) > 0:
                target = dict_target['s_url'][0]
            else:
                target = '/'

        # form cannot be generated if target is unknown
        if target is None:
            self.log_error('target url is not passed')
            self.send_response(500)
            return

        my_path = os.path.abspath(os.path.dirname(os.path.abspath(__file__))) + "/login-page/index.html"
        html_str = open(my_path, "r").read()

        self.send_response(200)
        self.end_headers()
        self.wfile.write(ensure_bytes(html_str.replace('TARGET', cgi.escape(target))))

    # processes posted form and sets the cookie with login/password
    def do_POST(self):

        # prepare arguments for cgi module to read posted form
        env = {'REQUEST_METHOD': 'POST',
               'CONTENT_TYPE': self.headers['Content-Type'], }

        # read the form contents
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                environ=env)

        # extract required fields
        user = form.getvalue('username')
        passwd = form.getvalue('password')
        target = form.getvalue('target')

        if user is not None and passwd is not None and target is not None:
            encryption_key = os.getenv('ENCRYPTION_KEY')
            if encryption_key is None or encryption_key == '':
                self.send_response(500)
                self.end_headers()
                self.wfile.write(ensure_bytes('required "ENCRYPTION_KEY" env was not set'))
                return

            # form is filled, set the cookie and redirect to target
            # so that auth daemon will be able to use information from cookie

            self.send_response(302)

            enc = base64.b64encode(ensure_bytes(user + ':' + passwd))
            if sys.version_info.major == 3:
                enc = enc.decode()

            fernet = Fernet(encryption_key)
            auth_cookie_encrypted = fernet.encrypt(ensure_bytes(enc)).decode('utf-8')

            self.send_header('Set-Cookie', 'nginxauth=' + auth_cookie_encrypted + '; httponly')

            self.send_header('Location', target)
            self.end_headers()

            return

        self.log_error('some form fields are not provided')
        self.auth_form(target)

    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        sys.stdout.write("%s - - [%s] %s\n" % (addr,
                                               self.log_date_time_string(), format % args))

    def log_error(self, format, *args):
        self.log_message(format, *args)


def exit_handler(signal, frame):
    sys.exit(0)


if __name__ == '__main__':
    server = AuthHTTPServer(Listen, AppHandler)
    signal.signal(signal.SIGINT, exit_handler)
    server.serve_forever()
