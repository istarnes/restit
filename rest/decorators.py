import sys

from functools import wraps
from django.core.urlresolvers import RegexURLResolver
from django.conf.urls import url as dcud_url
from django.shortcuts import Http404
from django.http import HttpResponseRedirect
from django.utils.decorators import available_attrs
from django.utils.cache import patch_cache_control, add_never_cache_headers, patch_vary_headers

from django.conf import settings
from rest.views import restStatus
from rest.models import RestError
from rest import helpers

from django.views.decorators.csrf import csrf_exempt

from rest.mail import render_to_mail

from account.models import AuthToken, Member

from datetime import datetime, timedelta
from auditlog.models import PersistentLog

import importlib
import threading
import traceback

# background task (no return)
def async(func):
	"""
	Execute the function asynchronously in a separate thread
	"""
	@wraps(func)
	def inner(*args, **kwargs):
		t = threading.Thread(target=func, args=args, kwargs=kwargs)
		t.daemon = True
		t.start()
	return inner


def postpone(function):
  def decorator(*args, **kwargs):
	t = threading.Thread(target = function, args=args, kwargs=kwargs)
	t.daemon = True
	t.start()
  return decorator

#
# Annotate a view with the URL that points to it
#

def rest_error_catcher(func, request, *args, **kwargs):
	try:
		return func(request, *args, **kwargs)
	except RestError as err:
		return restStatus(request, False, error=err.reason, error_code=err.code)
	except Exception as err:
		# TODO email errors to admins
		stack = str(traceback.format_exc())
		host = request.get_host()
		try:
			body = request.body
		except:
			body = request.DATA.asDict()

		PersistentLog.logError(stack, request, component="rest", action="error")
		# print "--- REST ERROR ---"
		# print stack
		# print "------------------"
		if hasattr(settings, "NOTIFY_REST_ERRORS") and settings.NOTIFY_REST_ERRORS:
			context = {
					   "to": settings.NOTIFY_REST_ERRORS,
					   "request": request,
					   "terminal": "",
					   "host": host,
					   "subject": "REST Error: {0}".format(host),
					   "error": str(err),
					   "stack": stack,
					   "user": str(request.user),
					   "body": body,
					   "meta": request.META,
					   "params": request.DATA
					}

			if hasattr(request, "terminal"):
				context["terminal"] = str(request.terminal)
			# try:
			emails = Member.GetWithPermission("rest_errors", email_list=True)
			if len(emails):
				context["to"] = emails
			if type(context["to"]) is list and len(context["to"]):
				render_to_mail("email/error", context)
		return restStatus(request, False, error=str(err))
	return restStatus(request, False)


def dispatcher (request, *args, **kwargs):
	module = kwargs.pop('__MODULE')
	pattern = kwargs.pop('__PATTERN')
	method = request.method
	if request.method == 'HEAD':
		method = 'GET'
	key = pattern + '__' + method
	if key in module.urlpattern_methods:
		return rest_error_catcher(module.urlpattern_methods[key], request, *args, **kwargs)
	print module.urlpattern_methods
	raise Http404

def _url_method(pattern, method=None, *args, **kwargs):
	"""
	Register a view handler for a specific HTTP method
	"""
	caller_filename = sys._getframe(2).f_code.co_filename
	module = None
	for m in sys.modules.values():
		if m and '__file__' in m.__dict__ and m.__file__.startswith(caller_filename):
			module = m
			break
	# print caller_filename
	# print method.__doc__
	# print "{0}/{1}".format(module.__name__, pattern)
	def _wrapper(f):
		new_pattern = True
		if module:
			rpc_root_module = module
			if module.__name__.count('.') > 1:
				# this means we are not in root
				# print module.__name__
				root_name = module.__name__.split('.')[0]
				# print "importing {0}.rpc".format(root_name)
				rpc_root_module = importlib.import_module(root_name + ".rpc")
			# print "{0}/{1}".format(rpc_root_module.__name__, pattern)
			elif not module.__name__.endswith(".rpc") and module.__name__.count('.'):
				# print module.__name__
				root_name = module.__name__.split('.')[0]
				# print "importing {0}.rpc".format(root_name)
				rpc_root_module = importlib.import_module(root_name + ".rpc")

			if 'urlpatterns' not in rpc_root_module.__dict__:
				rpc_root_module.urlpatterns = []
			if method and 'urlpattern_methods' not in rpc_root_module.__dict__:
				rpc_root_module.urlpattern_methods = {}
			elif method and pattern + '__' in rpc_root_module.urlpattern_methods:
				new_pattern = False

			if method:
				rpc_root_module.urlpattern_methods[pattern + '__' + method] = f

			if new_pattern:
				if method:
					func = dispatcher
					func.csrf_exempt = True
					rpc_root_module.urlpattern_methods[pattern + '__'] = True
					if not 'kwargs' in kwargs:
						kwargs['kwargs'] = {}
					kwargs['kwargs']['__MODULE'] = rpc_root_module
					kwargs['kwargs']['__PATTERN'] = pattern
				else:
					func = f
				if type(pattern) not in [unicode, str]:
					print "NOT A STRING"
					print pattern
				rpc_root_module.urlpatterns += [dcud_url(pattern, func, *args, **kwargs)]
			f.__url__ = (method, pattern)
			f.csrf_exempt = True
		return f
	_wrapper.caller_filename = "{0}/{1}".format(module.__name__, pattern)
	return _wrapper

def url(pattern, *args, **kwargs):
	"""
	Usage:
	@url(r'^users$')
	def get_user_list(request):
		...
	"""
	return _url_method(pattern, *args, **kwargs)

def urlGET(pattern, *args, **kwargs):
	"""
	Register GET handler for url pattern
	"""
	return _url_method(pattern, 'GET', *args, **kwargs)

def urlPUT(pattern, *args, **kwargs):
	"""
	Register PUT handler for url pattern
	"""
	return _url_method(pattern, 'PUT', *args, **kwargs)

def urlPOST(pattern, *args, **kwargs):
	"""
	Register POST handler for url pattern
	"""
	return _url_method(pattern, 'POST', *args, **kwargs)

def urlPOST_NOCSRF(pattern, *args, **kwargs):
	"""
	Register POST handler for url pattern
	"""
	return _url_method(pattern, 'POST', *args, **kwargs)

def urlDELETE(pattern, *args, **kwargs):
	"""
	Register DELETE handler for url pattern
	"""
	return _url_method(pattern, 'DELETE', *args, **kwargs)


#
# Continue the @url decorator pattern into sub-modules, if desired
#

def include_urlpatterns(regex, module):
	"""
	Usage:

	# in top-level module code:
	urlpatterns = include_urlpatterns(r'^profile/', 'apps.myapp.views.profile')
	"""
	return [RegexURLResolver(regex, module)]

#
# patched django decorators check if return is httpresponse
#

def cache_control(**kwargs):
	def _cache_controller(viewfunc):
		@wraps(viewfunc, assigned=available_attrs(viewfunc))
		def _cache_controlled(request, *args, **kw):
			response = viewfunc(request, *args, **kw)
			if hasattr(response, 'has_header'): # check if response is httpresponse
				patch_cache_control(response, **kwargs)
			return response
		return _cache_controlled
	return _cache_controller


def never_cache(view_func):
	@wraps(view_func, assigned=available_attrs(view_func))
	def _wrapped_view_func(request, *args, **kwargs):
		response = view_func(request, *args, **kwargs)
		if hasattr(response, 'has_header'): # check if response is httpresponse
			add_never_cache_headers(response)
		return response
	return _wrapped_view_func

def vary_on_headers(*headers):
	def decorator(func):
		@wraps(func, assigned=available_attrs(func))
		def inner_func(*args, **kwargs):
			response = func(*args, **kwargs)
			if hasattr(response, 'has_header'): # check if response is httpresponse
				patch_vary_headers(response, headers)
			return response
		return inner_func
	return decorator

def vary_on_cookie(func):
	@wraps(func, assigned=available_attrs(func))
	def inner_func(*args, **kwargs):
		response = func(*args, **kwargs)
		if hasattr(response, 'has_header'): # check if response is httpresponse
			patch_vary_headers(response, ('Cookie',))
		return response
	return inner_func

def force_ssl(func):
	@wraps(func, assigned=available_attrs(func))
	def inner_func(request=None, *args, **kwargs):
		if (not settings.DEBUG) and request and not request.is_secure():
			url = request.build_absolute_uri()
			return HttpResponseRedirect(url.replace('http://', 'https://'))

		response = func(request, *args, **kwargs)
		return response
	return inner_func


def login_required(func):
	@wraps(func, assigned=available_attrs(func))
	def inner_func(request=None, *args, **kwargs):
		if not request.user.is_authenticated():
			return restStatus(request, False, error="permission denied", error_code=401)

		if not hasattr(request, 'member'):
			request.member, request.group = request.user.__class__.getMemberGroup(request, False, False)

		return rest_error_catcher(func, request, *args, **kwargs)
	return inner_func


def login_optional(func):
	@wraps(func, assigned=available_attrs(func))
	def inner_func(request=None, *args, **kwargs):
		if not hasattr(request, "member"):
			if not request.user.is_authenticated():
				request.member = None
				if not hasattr(request, "group"):
					request.group = None 
				return func(request, *args, **kwargs)
			request.member, request.group = request.user.__class__.getMemberGroup(request, False, False)

		return rest_error_catcher(func, request, *args, **kwargs)
	return inner_func

def staff_required(func):
	@wraps(func, assigned=available_attrs(func))
	def inner_func(request=None, *args, **kwargs):
		if not request.user.is_authenticated() or not request.user.is_staff:
			return restStatus(request, False, error="staff request denied", error_code=402)
		
		if not hasattr(request, 'member'):
			request.member, request.group = request.user.__class__.getMemberGroup(request, False, False)

		return rest_error_catcher(func, request, *args, **kwargs)
	return inner_func

def ip_whitelist(func,*args,**kwargs):
	@wraps(func, assigned=available_attrs(func))
	def inner_func(request=None, *args, **kwargs):
		request_ip = request.META['REMOTE_ADDR']
		if request_ip not in settings.AUTHORIZED_IPS:
			return restStatus(request, False, error="permission denied")
		return rest_error_catcher(func, request, *args, **kwargs)
	return inner_func


def getAuthToken(request):
	token = request.DATA.get(["token", "auth_token", "authtoken"], None)
	if not token:
		token = request.META.get("x-authtoken", None)
	return token

def getMemberFromToken(request):
	token = getAuthToken(request)
	if token and len(token) > 4:
		atoken = AuthToken.objects.filter(token=token).last()
		# removed , token_ip=request.ip from above because ip changed.
		if atoken:
			request.member = atoken.membership.member
			request.group = atoken.membership.group	
	return request.member

def token_auth(func):
	@wraps(func, assigned=available_attrs(func))
	def inner_func(request=None, *args, **kwargs):
		getMemberFromToken(request)
			# TODO verify IP and account privledges
		return rest_error_catcher(func, request, *args, **kwargs)
	return inner_func

def token_auth_required(func):
	@wraps(func, assigned=available_attrs(func))
	def inner_func(request=None, *args, **kwargs):
		getMemberFromToken(request)
		if not request.member:
			return restStatus(request, False, error="token permission denied", error_code=601)
		return rest_error_catcher(func, request, *args, **kwargs)
	return inner_func

allow_tokens = token_auth
auth_required = token_auth_required

def periodicCheckListHas(list_obj, has_value):
	if type(list_obj) is list:
		return has_value in list_obj
	return list_obj == has_value

PERIODIC_FUNCS = []

def periodic(minute=None, hour=None, day=None, month=None, weekday=None, tz=None):
	"""
	supports minute=5 or minute=[5,10,20]
	"""
	def decorator(func):
		PERIODIC_FUNCS.append({
				"func":func,
				"minute":minute,
				"hour":hour,
				"day":day,
				"month":month,
				"weekday":weekday,
				"tz":tz
			})
		@wraps(func)
		def inner_func(force=False, verbose=False, now=None):
			if now is None:
				now = datetime.now()
			if force:
				return func(force, verbose, now)
			if tz:
				now = helpers.convertToLocalTime(tz, now)
			# lets create our when
			if minute != None and not periodicCheckListHas(minute, now.minute):
				return False
			if hour != None and not periodicCheckListHas(hour, now.hour):
				return False
			if day != None and not periodicCheckListHas(day, now.day):
				return False
			if month != None and not periodicCheckListHas(month, now.month):
				return False
			if weekday != None and not periodicCheckListHas(weekday, now.weekday()):
				return False
			return func(force, verbose, now)
		return inner_func
	return decorator

