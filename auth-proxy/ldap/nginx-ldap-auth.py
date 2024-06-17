#!/bin/sh
''''[ -z $LOG ] && export LOG=/dev/stdout # '''
''''which python  >/dev/null && exec python  -u "$0" "$@" >> $LOG 2>&1 # '''

# Copyright (C) 2014-2022 Nginx, Inc.

# pylint: disable=invalid-name
import sys
import os
import signal
import base64
import argparse
import ast
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import ldap
import ldap.filter

load_dotenv()

if sys.version_info.major == 2:
    from Cookie import BaseCookie
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
elif sys.version_info.major == 3:
    from http.cookies import BaseCookie
    from http.server import HTTPServer, BaseHTTPRequestHandler

if not hasattr(__builtins__, "basestring"):
    basestring = (str, bytes)


def ensure_bytes(data):
    return data if sys.version_info.major == 2 else data.encode("utf-8")


def ensure_string(data):
    return data if sys.version_info.major == 2 else data.decode("utf-8")


# Listen = ('localhost', 8888)
# Listen = "/tmp/auth.sock"    # Also uncomment lines in 'Requests are
# processed with UNIX sockets' section below

# -----------------------------------------------------------------------------
# Different request processing models: select one
# -----------------------------------------------------------------------------
# Requests are processed in separate thread

if sys.version_info.major == 2:
    from SocketServer import ThreadingMixIn
elif sys.version_info.major == 3:
    from socketserver import ThreadingMixIn


class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass


# -----------------------------------------------------------------------------
# Requests are processed in separate process
# from SocketServer import ForkingMixIn
# class AuthHTTPServer(ForkingMixIn, HTTPServer):
#    pass
# -----------------------------------------------------------------------------
# Requests are processed with UNIX sockets
# import threading
# from SocketServer import ThreadingUnixStreamServer
# class AuthHTTPServer(ThreadingUnixStreamServer, HTTPServer):
#    pass
# -----------------------------------------------------------------------------


class AuthHandler(BaseHTTPRequestHandler):

    # Return True if request is processed and response sent, otherwise False
    # Set ctx['user'] and ctx['pass'] for authentication
    def do_GET(self):

        ctx = self.ctx

        ctx['action'] = 'input parameters check'
        for k, v in self.get_params().items():
            ctx[k] = self.headers.get(v[0], v[1])
            if ctx[k] is None:
                self.auth_failed(ctx, 'required "%s" header was not passed' % k)
                return True

        ctx['action'] = 'performing authorization'
        auth_header = self.headers.get('Authorization')
        auth_cookie = self.get_cookie(ctx['cookiename'])

        if auth_cookie is not None and auth_cookie != '':
            ctx['action'] = 'performing authorization with cookie'

            # decrypt auth_cookie with encryption key by Fernet
            ctx['encryption_key'] = os.getenv('ENCRYPTION_KEY')
            if not is_not_empty_str(ctx['encryption_key']):
                self.auth_failed(ctx, 'required "ENCRYPTION_KEY" env was not set')
                return True

            try:
                fernet = Fernet(ctx['encryption_key'])
                auth_cookie_base64 = fernet.decrypt(ensure_bytes(auth_cookie)).decode('utf-8')
            except:  # pylint: disable=bare-except
                self.auth_failed(ctx, 'decrypting auth cookie failed')
                return True

            auth_header = "Basic " + auth_cookie_base64
            self.log_message("using username/password from cookie %s" %
                             ctx['cookiename'])
        else:
            # Authorization header use base64 encoded username:password, no need to decrypt by Fernet
            self.log_message("using username/password from authorization header")

        if auth_header is None or not auth_header.lower().startswith('basic '):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="' + ctx['realm'] + '"')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            return True

        ctx['action'] = 'decoding credentials'

        try:
            auth_decoded = ensure_string(base64.b64decode(auth_header[6:]))
            user, passwd = auth_decoded.split(':', 1)

        except:  # pylint: disable=bare-except
            self.auth_failed(ctx)
            return True

        ctx['pass'] = passwd
        ctx['user'] = ldap.filter.escape_filter_chars(user)

        # Continue request processing
        return False

    def get_cookie(self, name):
        cookies = self.headers.get('Cookie')
        if cookies:
            authcookie = BaseCookie(cookies).get(name)
            if authcookie:
                return authcookie.value
            else:
                return None
        else:
            return None

    # Log the error and complete the request with appropriate status
    def auth_failed(self, ctx, errmsg=None):

        msg = 'Error while ' + ctx['action']
        if errmsg:
            msg += ': ' + errmsg

        ex, value, trace = sys.exc_info()  # pylint: disable=unused-variable

        if ex is not None:
            msg += ": " + str(value)

        if ctx.get('url'):
            msg += ', server="%s"' % ctx['url']

        if ctx.get('user'):
            msg += ', login="%s"' % ctx['user']

        self.log_error(msg)
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="' + ctx['realm'] + '"')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

    def get_params(self):
        return {}

    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        if not hasattr(self, 'ctx'):
            user = '-'
        else:
            user = self.ctx['user']

        sys.stdout.write("%s - %s [%s] %s\n" % (addr, user,
                                                self.log_date_time_string(), format % args))

    def log_error(self, format, *args):
        self.log_message(format, *args)


# Verify username/password against LDAP server
class LDAPAuthHandler(AuthHandler):
    # Parameters to put into self.ctx from the HTTP header of auth request
    params = {
        # parameter      header         default
        'realm': ('X-Ldap-Realm', 'Restricted'),
        'url': ('X-Ldap-URL', None),
        'starttls': ('X-Ldap-Starttls', 'false'),
        'disable_referrals': ('X-Ldap-DisableReferrals', 'false'),
        'basedn': ('X-Ldap-BaseDN', None),
        'template': ('X-Ldap-Template', '(cn=%(username)s)'),
        'binddn': ('X-Ldap-BindDN', ''),
        'bindpasswd': ('X-Ldap-BindPass', ''),
        'cookiename': ('X-CookieName', ''),
        'memberof': ('X-Ldap-Member-Of', None),
        'group_search_filter': ('X-Ldap-Group-Search-Filter', None),
        'group_search_basedn': ('X-Ldap-Group-Search-BaseDN', None),
        'group_search_filter_user_attribute': ('X-Ldap-Group-Search-Filter-User-Attribute', None),
        'group_mappings': ('X-Ldap-Group-Mappings', None),
    }

    @classmethod
    def set_params(cls, params):
        cls.params = params

    def get_params(self):
        return self.params

    # GET handler for the authentication request
    def do_GET(self):

        ctx = dict()
        self.ctx = ctx

        ctx['action'] = 'initializing basic auth handler'
        ctx['user'] = '-'

        if AuthHandler.do_GET(self):
            # request already processed
            return

        ctx['action'] = 'empty password check'
        if not ctx['pass']:
            self.auth_failed(ctx, 'attempt to use empty password')
            return

        try:
            # check that uri and baseDn are set
            # either from cli or a request
            if not ctx['url']:
                self.log_message('LDAP URL is not set!')
                return
            if not ctx['basedn']:
                self.log_message('LDAP baseDN is not set!')
                return

            ctx['action'] = 'initializing LDAP connection'
            ldap_obj = ldap.initialize(ctx['url']);

            # Python-ldap module documentation advises to always
            # explicitely set the LDAP version to use after running
            # initialize() and recommends using LDAPv3. (LDAPv2 is
            # deprecated since 2003 as per RFC3494)
            #
            # Also, the STARTTLS extension requires the
            # use of LDAPv3 (RFC2830).
            ldap_obj.protocol_version = ldap.VERSION3

            # Establish a STARTTLS connection if required by the
            # headers.
            if ctx['starttls'] == 'true':
                ldap_obj.start_tls_s()

            # See https://www.python-ldap.org/en/latest/faq.html
            if ctx['disable_referrals'] == 'true':
                ldap_obj.set_option(ldap.OPT_REFERRALS, 0)

            ctx['action'] = 'binding as search user'
            ldap_obj.bind_s(ctx['binddn'], ctx['bindpasswd'], ldap.AUTH_SIMPLE)

            ctx['action'] = 'preparing search filter'
            searchfilter = ctx['template'] % {'username': ctx['user']}

            self.log_message(('searching on server "%s" with base dn ' + \
                              '"%s" with filter "%s"') %
                             (ctx['url'], ctx['basedn'], searchfilter))

            ctx['action'] = 'running search query'
            results = ldap_obj.search_s(ctx['basedn'],
                                        ldap.SCOPE_SUBTREE,
                                        searchfilter,
                                        ['objectclass',
                                         ctx['memberof'],
                                         ctx['group_search_filter_user_attribute']], 0)

            ctx['action'] = 'verifying search query results'

            nres = len(results)

            if nres < 1:
                self.auth_failed(ctx, 'no objects found')
                return

            if nres > 1:
                self.log_message("note: filter match multiple objects: %d, using first" % nres)

            user_entry = results[0]
            ldap_dn = user_entry[0]
            attrs = user_entry[1]

            if ldap_dn is None:
                self.auth_failed(ctx, 'matched object has no dn')
                return

            self.log_message('attempting to bind using dn "%s"' % (ldap_dn))

            ctx['action'] = 'binding as an existing user "%s"' % ldap_dn

            ldap_obj.bind_s(ldap_dn, ctx['pass'], ldap.AUTH_SIMPLE)

            self.log_message('Auth OK for user "%s"' % (ctx['user']))

            # get group_dn
            group_dns = []
            if is_not_empty_str(ctx['memberof']):
                ctx['action'] = ('get group_dn from memberof value "%s"'
                                 % (''.join(list(map(lambda memberof: ensure_string(memberof),
                                                     attrs[ctx['memberof']] or [])))))
                group_dns = attrs[ctx['memberof']]
            elif is_not_empty_str(ctx['group_search_filter']):
                if is_not_empty_str(ctx['group_search_basedn']):
                    group_search_basedn = ctx['group_search_basedn']
                else:
                    group_search_basedn = ctx['basedn']

                ctx['action'] = 'preparing group search filter'
                group_searchfilter = ctx['group_search_filter'] % attrs[ctx['group_search_filter_user_attribute']][
                    0].decode('utf-8')

                ctx['action'] = 'binding as search user'
                ldap_obj.bind_s(ctx['binddn'], ctx['bindpasswd'], ldap.AUTH_SIMPLE)

                ctx['action'] = 'running group search query'
                group_results = ldap_obj.search_s(group_search_basedn, ldap.SCOPE_SUBTREE,
                                                  group_searchfilter,
                                                  ['objectclass'],
                                                  1)

                ctx['action'] = 'verifying group search query results'

                group_results_len = len(group_results)

                if group_results_len < 1:
                    self.auth_failed(ctx, 'no group found')
                    return

                if sys.version_info.major == 2:
                    group_dns = map(lambda group_entry: group_entry[0], group_results)
                elif sys.version_info.major == 3:
                    group_dns = list(map(lambda group_entry: group_entry[0], group_results))

            # map group_dns to role
            role = None
            if len(group_dns) < 1:
                self.auth_failed(ctx, "note: no group_dn found")
                return

            ctx['action'] = 'verifying group_mappings'
            if not is_not_empty_str(ctx['group_mappings']):
                self.auth_failed(ctx, 'no group mappings')
                return
            else:
                ctx['action'] = 'mapping group_dn to role'
                group_mappings = ast.literal_eval(ctx['group_mappings'])
                if isinstance(group_mappings, (list, tuple)):
                    group_dns = list(map(lambda group_dn_item: ensure_string(group_dn_item), group_dns))
                    group_dns_dict = dict(zip(group_dns, [True] * len(group_dns)))
                    for group_mapping in group_mappings:
                        if not (is_not_empty_str(group_mapping[0]) and is_not_empty_str(group_mapping[1])):
                            continue
                        group_dn = group_mapping[0]

                        group_matched = False
                        if sys.version_info.major == 2:
                            group_matched = group_dn == '*' or group_dns_dict.has_key(group_dn)
                        elif sys.version_info.major == 3:
                            group_matched = group_dn == '*' or group_dns_dict.__contains__(group_dn)
                        if group_matched:
                            role = group_mapping[1]
                            self.log_message('group_dn "%s" mapped to role "%s"' % (group_dn, role))
                            break
                    if role is None:
                        self.auth_failed(ctx, 'no role mapped for group_dns "%s"' % group_dns)
                        return
                else:
                    self.auth_failed(ctx, 'no valid group mappings')
                    return

            # Successfully authenticated user
            self.send_response(200)
            self.send_header('X-DATASIGHT-ROLE', role)
            self.send_header('X-DATASIGHT-USER', (ctx['user']))
            self.end_headers()

        except:  # pylint: disable=bare-except
            self.auth_failed(ctx)


def is_not_empty_str(s):
    return s and len(s) > 0


def exit_handler(signal, frame):
    global Listen

    if isinstance(Listen, basestring):
        try:
            os.unlink(Listen)
        except:  # pylint: disable=bare-except
            ex, value, trace = sys.exc_info()  # pylint: disable=unused-variable
            sys.stderr.write('Failed to remove socket "%s": %s\n' %
                             (Listen, str(value)))
            sys.stderr.flush()
    sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="""Simple Nginx LDAP authentication helper.""")
    # Group for listen options:
    group = parser.add_argument_group("Listen options")
    group.add_argument('--host', metavar="hostname",
                       default="localhost", help="host to bind (Default: localhost)")
    group.add_argument('-p', '--port', metavar="port", type=int,
                       default=8888, help="port to bind (Default: 8888)")
    # ldap options:
    group = parser.add_argument_group(title="LDAP options")
    group.add_argument('-u', '--url', metavar="URL",
                       default="ldap://localhost:389",
                       help=("LDAP URI to query (Default: ldap://localhost:389)"))
    group.add_argument('-s', '--starttls', metavar="starttls",
                       default="false",
                       help=("Establish a STARTTLS protected session (Default: false)"))
    group.add_argument('--disable-referrals', metavar="disable_referrals",
                       default="false",
                       help=("Sets ldap.OPT_REFERRALS to zero (Default: false)"))
    group.add_argument('-b', metavar="baseDn", dest="basedn", default='',
                       help="LDAP base dn (Default: unset)")
    group.add_argument('-D', metavar="bindDn", dest="binddn", default='',
                       help="LDAP bind DN (Default: anonymous)")
    group.add_argument('-w', metavar="passwd", dest="bindpw", default='',
                       help="LDAP password for the bind DN (Default: unset)")
    group.add_argument('-f', '--filter', metavar='filter',
                       default='(cn=%(username)s)',
                       help="LDAP filter (Default: cn=%%(username)s)")
    group.add_argument('--memberof', metavar='memberof',
                       default='',
                       help="LDAP memberOf attribute name (Default: unset")
    group.add_argument('--group-search-filter', metavar='groupSearchFilter', dest="group_search_filter",
                       default='',
                       help="LDAP group search filter (Default: unset")
    group.add_argument('--group-search-base-dn', metavar='groupSearchBaseDN', dest="group_search_basedn",
                       default='',
                       help="LDAP group search base dn (Default: base dn argument")
    group.add_argument('--group-search-filter-user-attribute', metavar='groupSearchFilterUserAttribute',
                       dest="group_search_filter_user_attribute",
                       default='',
                       help="LDAP group search filter user attribute (Default: unset")
    group.add_argument('--group-mappings', metavar='groupMappings',
                       dest="group_mappings",
                       default='',
                       help="LDAP group mappings (Default: unset")
    # http options:
    group = parser.add_argument_group(title="HTTP options")
    group.add_argument('-R', '--realm', metavar='"Restricted Area"',
                       default="Restricted", help='HTTP auth realm (Default: "Restricted")')
    group.add_argument('-c', '--cookie', metavar="cookiename",
                       default="", help="HTTP cookie name to set in (Default: unset)")

    args = parser.parse_args()
    global Listen
    Listen = (args.host, args.port)
    auth_params = {
        'realm': ('X-Ldap-Realm', args.realm),
        'url': ('X-Ldap-URL', args.url),
        'starttls': ('X-Ldap-Starttls', args.starttls),
        'disable_referrals': ('X-Ldap-DisableReferrals', args.disable_referrals),
        'basedn': ('X-Ldap-BaseDN', args.basedn),
        'template': ('X-Ldap-Template', args.filter),
        'binddn': ('X-Ldap-BindDN', args.binddn),
        'bindpasswd': ('X-Ldap-BindPass', args.bindpw),
        'cookiename': ('X-CookieName', args.cookie),
        'memberof': ('X-Ldap-Member-Of', args.memberof),
        'group_search_filter': ('X-Ldap-Group-Search-Filter', args.group_search_filter),
        'group_search_basedn': ('X-Ldap-Group-Search-BaseDN', args.group_search_basedn),
        'group_search_filter_user_attribute': (
            'X-Ldap-Group-Search-Filter-User-Attribute', args.group_search_filter_user_attribute),
        'group_mappings': ('X-Ldap-Group-Mappings', args.group_mappings),
    }
    LDAPAuthHandler.set_params(auth_params)
    server = AuthHTTPServer(Listen, LDAPAuthHandler)
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    sys.stdout.write("Start listening on %s:%d...\n" % Listen)
    sys.stdout.flush()
    server.serve_forever()
