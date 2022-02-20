from django.conf import settings
from importlib import import_module
from threading import currentThread
import re

from datetime import datetime, date
import types

from django.utils.text import compress_string
from django import http

from rest import helpers as rest_helpers
from rest.RequestData import RequestData
from auditlog.models import PersistentLog

from django.contrib.sessions.models import Session
from django.core.cache import cache

from urllib.parse import urlparse

import time

from django.utils.cache import patch_vary_headers
from django.utils.http import http_date

import requests

# HACK FOR SameSite
from http.cookies import Morsel
Morsel._reserved['samesite'] = 'SameSite'
SESSION_COOKIE_SAMESITE = getattr(settings, "SESSION_COOKIE_SAMESITE", None)
REMOTE_AUTH = getattr(settings, "REMOTE_AUTH", None)

def remoteAuth(request, token=None):
    from account.models import RemoteMember
    if token == None:
        token = request.DATA.get("rauth_token", None)
    if not token:
        return None
    resp = requests.post(REMOTE_AUTH, {"rauth_token": token})
    if resp.status_code == 200:
        data = resp.json()
        if data.get("status", False):
            data = data.get("data")
            remote_host = urlparse(REMOTE_AUTH).netloc
            member = RemoteMember.objects.filter(remote_id=data.get('id'), remote_host=remote_host).last()
            if not member:
                remote_username  = "{}@{}".format(data.get("username"), remote_host)
                member = RemoteMember(email=data.get('email'),
                    username=remote_username,
                    remote_id=data.get('id'),
                    remote_host=remote_host)
                member.save()
            member.update(**data)
            # print(("we gots a member {}".format(member.username)))
            return member
    return None

class SessionMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response
        engine = import_module(settings.SESSION_ENGINE)
        self.SessionStore = engine.SessionStore

    def __call__(self, request):
        self.process_request(request)
        response = self.get_response(request)
        self.process_response(request, response)
        return response

    def process_request(self, request):
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        # for key in request.COOKIES:
        #     print("cookie.{} = {}".format(key, request.COOKIES.get(key)))
        # # print(session_key)
        # print("session key: {}".format(session_key))
        # print("session SESSION_COOKIE_NAME: {}".format(settings.SESSION_COOKIE_NAME))

        secure_keys = getattr(settings, "SESSION_KEY_SECURE", True)
        if not secure_keys:
            if not session_key:
                session_key = request.META.get('HTTP_AUTHORIZATION', None)
                if session_key and session_key.count(" ") > 0:
                    # this is not a session key
                    session_key = None

            if not session_key:
                session_key = request.META.get('HTTP_X_SESSIONID', None)

            if not session_key:
                session_key = request.POST.get('SESSION_KEY', None)

            if not session_key:
                session_key = request.GET.get('SESSION_KEY', None)

        if session_key:
            request.session = self.SessionStore(session_key)
            if not request.session.exists(session_key):
                session_key = None
        request.session = self.SessionStore(session_key)
        # check if session key is dead?
        # print(request.session)

    def process_response(self, request, response):
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie or delete
        the session cookie if the session has been emptied.
        """
        try:
            accessed = request.session.accessed
            modified = request.session.modified
            empty = request.session.is_empty()
        except AttributeError as err:
            # print("session attribute error: {}".format(str(err)))
            pass
        else:
            # First check if we need to delete this cookie.
            # The session should be deleted only if the session is entirely empty
            if settings.SESSION_COOKIE_NAME in request.COOKIES and empty:
                response.delete_cookie(settings.SESSION_COOKIE_NAME,
                    domain=settings.SESSION_COOKIE_DOMAIN)
            else:
                if accessed:
                    patch_vary_headers(response, ('Cookie',))
                if (modified or settings.SESSION_SAVE_EVERY_REQUEST) and not empty:
                    if request.session.get_expire_at_browser_close():
                        max_age = None
                        expires = None
                    else:
                        max_age = request.session.get_expiry_age()
                        expires_time = time.time() + max_age
                        expires = http_date(expires_time)
                    # Save the session data and refresh the client cookie.
                    # Skip session save for 500 responses, refs #3881.
                    if response.status_code != 500:
                        # print("saving session: \n{}".format(request.session.session_key))
                        # print("session cooking domain: {}".format(settings.SESSION_COOKIE_DOMAIN))
                        # print("session cooking path: {}".format(settings.SESSION_COOKIE_PATH))
                        # print("session max_age: {}".format(max_age))
                        request.session.save()
                        response.set_cookie(settings.SESSION_COOKIE_NAME,
                                request.session.session_key, max_age=max_age,
                                expires=expires, domain=settings.SESSION_COOKIE_DOMAIN,
                                path=settings.SESSION_COOKIE_PATH,
                                secure=settings.SESSION_COOKIE_SECURE or None,
                                httponly=settings.SESSION_COOKIE_HTTPONLY or None)
                        if SESSION_COOKIE_SAMESITE:
                            # now lets verify browser supports it
                            ua = request.META.get('HTTP_USER_AGENT', '')
                            if "rome/" in ua:
                                p = ua.find("rome/")+5
                                ver = ua[p:p+2]
                                if ver.isdigit():
                                    if int(ver) < 75:
                                        # this is really old version of chrome
                                        print(("warning, detected old version of chrome! {}".format(ver)))
                                        return response
                            response.cookies[settings.SESSION_COOKIE_NAME]["samesite"] = SESSION_COOKIE_SAMESITE
        return response

if hasattr(settings, "CORS_SHARING_ALLOWED_ORIGINS"):
    CORS_SHARING_ALLOWED_ORIGINS = settings.CORS_SHARING_ALLOWED_ORIGINS
else:
    CORS_SHARING_ALLOWED_ORIGINS = '*'

if hasattr(settings, "CORS_SHARING_ALLOWED_METHODS"):
    CORS_SHARING_ALLOWED_METHODS = settings.CORS_SHARING_ALLOWED_METHODS
else:
    CORS_SHARING_ALLOWED_METHODS = ['POST','GET','OPTIONS', 'PUT', 'DELETE']

if hasattr(settings, "CORS_SHARING_ALLOWED_HEADERS"):
    CORS_SHARING_ALLOWED_HEADERS = settings.CORS_SHARING_ALLOWED_HEADERS
else:
    CORS_SHARING_ALLOWED_HEADERS = [
        'accept',
        'accept-encoding',
        'authorization',
        'content-type',
        'dnt',
        'origin',
        'user-agent',
        'x-authtoken',
        'x-csrftoken',
        'x-sessionid',
        'x-requested-with']

CORS_ALLOW_CREDENTIALS = getattr(settings, "CORS_ALLOW_CREDENTIALS", True)

_requests = {}

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_request():
    i = currentThread().ident
    if i in _requests:
        return _requests[i]
    return None

def setLogModel(self, component, pk):
    # this method allows for updating the component to associate a log with
    if not pk or (self._log_pk == pk):
        return
    self._log_component = component
    self._log_pk = pk
    if hasattr(self, "request_log"):
        self.request_log.component = component
        self.request_log.pkey = pk
        self.request_log.save()


class GlobalRequestMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.process_request(request)
        response = response or self.get_response(request)
        return response

    def process_locale(self, request):
        locale = settings.DEFAULT_LANGUAGE
        if request.method == "POST":
            data = request.POST
        else:
            data = request.GET

        if "lang" in data:
            locale = data.get("lang")
        elif "locale" in data:
            locale = data.get("locale")
        elif 'HTTP_ACCEPT_LANGUAGE' in request.META:
            locale = request.META['HTTP_ACCEPT_LANGUAGE']

        lang = [x.strip()[:2] for x in locale.split(',')]
        if len(lang):
            request.LANGUAGE_CODE = lang[0]
        else:
            # we do this for when we get bad values above like empty strings
            request.LANGUAGE_CODE = settings.DEFAULT_LANGUAGE

        if "-" in request.LANGUAGE_CODE:
            request.COUNTRY_CODE = request.LANGUAGE_CODE.split('-')[0]
        else:
            request.COUNTRY_CODE = request.LANGUAGE_CODE

    def process_request(self, request):
        _requests[currentThread().ident] = request
        # print "PROCESSING REQUEST..."
        request.ip = get_client_ip(request)
        # print "IP: " + request.ip
        request.setLogModel = types.MethodType(setLogModel, request)
        request._log_component = None
        request._log_pk = None
        request.logger = rest_helpers.getLoggerByRequest(request)
        try:
            RequestData.upgradeRequest(request)
            if request.user.is_authenticated:
                request.member, request.group = request.user.__class__.getMemberGroup(request, False, False)
            elif REMOTE_AUTH:
                request.member = remoteAuth(request)
                if request.member:
                    request.user = request.member
                if not hasattr(request, "group"):
                    request.group = None
            else:
                request.member = None
                if not hasattr(request, "group"):
                    request.group = None
        except Exception:
            rest_helpers.log_exception("GlobalRequestMiddleware")
            # print((str(err)))

        if settings.PROCESS_LOCALE:
            self.process_locale(request)


class CorsMiddleware(object):
    """
        This middleware allows cross-domain XHR using the html5 postMessage API.

        Access-Control-Allow-Origin: http://foo.example
        Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # rest_helpers.log_print(dict(request.META))
        # check if preflight header, then return HTTP 200
        if request.method.lower() == "options" and 'HTTP_ACCESS_CONTROL_REQUEST_METHOD' in request.META:
            response = http.HttpResponse()
        else:
            response = self.get_response(request)
        response = self.updateResponse(request, response)
        # rest_helpers.log_print(response._headers)
        return response

    def getAllowedOrigin(self, request):
        origin = request.META.get('HTTP_ORIGIN', None)
        if origin:
            if CORS_SHARING_ALLOWED_ORIGINS == '*':
                return origin
            host = urlparse(origin)
            if 'localhost' in host:
                host = 'localhost'
            if type(CORS_SHARING_ALLOWED_ORIGINS) is list:
                if host in CORS_SHARING_ALLOWED_ORIGINS:
                    return origin
            elif type(CORS_SHARING_ALLOWED_ORIGINS) in [str, str]:
                if host == CORS_SHARING_ALLOWED_ORIGINS:
                    return origin

        host = request.META.get('HTTP_HOST', None)
        if not host:
            return None
        return "https://{}".format(host)

    def updateResponse(self, request, response):
        # rest_helpers.log_print("CORS: updating response")
        if CORS_ALLOW_CREDENTIALS:
            response['Access-Control-Allow-Credentials'] = 'true'
        else:
            response['Access-Control-Allow-Credentials'] = 'false'

        allowed_origin = self.getAllowedOrigin(request)
        if allowed_origin:
            # rest_helpers.log_print('Access-Control-Allow-Origin: {}'.format(allowed_origin))
            response['Access-Control-Allow-Origin']  = allowed_origin
            patch_vary_headers(response, ['Origin'])

        if request.method.lower() == "options":
            response['Access-Control-Allow-Headers'] = ",".join( CORS_SHARING_ALLOWED_HEADERS )
            response['Access-Control-Allow-Methods'] = ",".join( CORS_SHARING_ALLOWED_METHODS )
        return response

