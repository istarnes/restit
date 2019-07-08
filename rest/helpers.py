import sys
import re
import time
from datetime import date, datetime, timedelta
from django.conf import settings
from django.db.models import Count, Q, Avg, Sum, Max, Min
from StringIO import StringIO
from uberdict import UberDict
from datem import *

try:
	from fuzzywuzzy import fuzz
except:
	fuzz = None

# THIS NEEDS A NEW HOME
import shutil
import tempfile

import random, string

class TemporaryDirectory(object):
	"""Context manager for tempfile.mkdtemp() so it's usable with "with" statement."""
	def __enter__(self):
		self.name = tempfile.mkdtemp()
		return self.name

	def __exit__(self, exc_type, exc_value, traceback):
		shutil.rmtree(self.name)


# Some mobile browsers which look like desktop browsers.
RE_MOBILE = re.compile(r"(iphone|ipod|blackberry|android|palm|windows\s+ce)", re.I)
RE_DESKTOP = re.compile(r"(windows|linux|os\s+[x9]|solaris|bsd)", re.I)
RE_BOT = re.compile(r"(spider|crawl|slurp|bot)", re.I)
RE_SOCIAL = re.compile(r"(facebookexternalhit/[0-9]|LinkedInBot|Twitterbot|Pinterest|Google.*snippet)", re.I)
RE_SCRAPERS = re.compile(r"(FlipboardProxy|Slurp|PaperLiBot|TweetmemeBot|MetaURI|Embedly)", re.I)

RE_EMAIL = re.compile(r"[^@]+@[^@]+\.[^@]+", re.I)

DEBUG_DATETIME = False
if hasattr(settings, "DEBUG_DATETIME"):
		DEBUG_DATETIME = getattr(settings, "DEBUG_DATETIME")

def graphBuilderInplace(part, field, graph):
	output = []
	if not graph.has_key(part):
		return output
	graph_part = graph[part]
	for f in graph_part:
		if type(f) is tuple:
			f1, f2 = f
			output.append(("{0}.{1}", "{2}").format(field, f1, f2))
		else:
			output.append("{0}.{1}".format(field, f))
	return output


def graphBuilder(root_graph, field, graph):
	for part in ["fields", "recurse_into"]:
		if not graph.has_key(part):
			continue
		graph_part = graph[part]
		if not root_graph.has_key(part):
			root_graph[part] = []
		root_part = root_graph[part]
		for f in graph_part:
			if type(f) is tuple:
				f1, f2 = f
				root_part.append(("{0}.{1}".format(field, f1), f2))
			else:
				root_part.append("{0}.{1}".format(field, f))
	return root_graph

def fuzzyMatch(a, b):
	if fuzz:
		if a and b:
			a = a.lower()
			b = b.lower()
			return max(fuzz.token_set_ratio(a,b),fuzz.partial_ratio(a,b))
		return 0
	print "MISSING FUZZWUZZY MODULE"
	return 100

def isValidEmail(email):
	return bool(RE_EMAIL.search(email))

def getProtocol(request):
	if request.is_secure():
		return "https://"
	return "http://"

def getSocialReferer(request):
	referer = getReferer(request)
	if referer and "://" in referer:
		r = referer.split("/")
		domain = r[2]
		if domain in ["t.co", "twitter.com"]:
			return "twitter"
		elif domain in ["facebook.com", "m.facebook.com"]:
			return "facebook"
		elif domain in ["linkedin.com", "lnkd.in"]:
			return "linkedin"
		elif domain in ["pinterest.com"]:
			return "pinterest"
		elif domain in ["plus.google.com", "plus.url.google.com"]:
			return "googleplus"	
		elif domain in ["www.google.com"]:
			return "google"
		elif domain in ["bing.com", "www.bing.com"]:
			return "bing"
		return domain
	return referer	

def getReferer(request):
	return request.META.get('HTTP_REFERER')

def getRemoteIP(request):
	x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
	if x_forwarded_for:
		ip = x_forwarded_for.split(',')[0]
	else:
		ip = request.META.get('REMOTE_ADDR')
	return ip

def getUserAgent(request):
  # Some mobile browsers put the User-Agent in a HTTP-X header
  return request.META.get('HTTP_X_OPERAMINI_PHONE_UA') or \
		 request.META.get('HTTP_X_SKYFIRE_PHONE') or \
		 request.META.get('HTTP_USER_AGENT', '')

def getSocialAgent(request):
	user_agent = getUserAgent(request).lower()
	if "facebook" in user_agent:
		return "facebook"
	if "linkedin" in user_agent:
		return "linkedin"
	if "twitter" in user_agent:
		return "twitter"
	if "pinterest" in user_agent:
		return "pinterest"
	if "google" in user_agent:
		return "google"
	if "yahoo" in user_agent:
		return "yahoo"
	if "flipboard" in user_agent:
		return "flipboard"
	if "embedly" in user_agent:
		return "embedly"
	return "unknown"

def agentHas(request, keyword):
	return keyword.lower() in getUserAgent(request).lower()

def isSocialScraper(request):
	user_agent = getUserAgent(request)
	return bool(RE_SCRAPERS.search(user_agent))	

def isSocialAgent(request):
	user_agent = getUserAgent(request)
	return bool(RE_SOCIAL.search(user_agent))

def isBotAgent(request):
	user_agent = getUserAgent(request)
	return bool(RE_BOT.search(user_agent))

def isMobile(request):
	user_agent = getUserAgent(request)
	return bool(RE_MOBILE.search(user_agent)) and not bool(RE_BOT.search(user_agent))
   
def isDesktopAgent(request):
	user_agent = getUserAgent(request)
	return not bool(RE_MOBILE.search(user_agent)) and bool(RE_DESKTOP.search(user_agent)) or bool(RE_BOT.search(user_agent))

def lowerKeys(x):
	if isinstance(x, list):
		return [lowerKeys(v) for v in x]
	elif isinstance(x, dict):
		return dict((k.lower(), lowerKeys(v)) for k, v in x.iteritems())
	return x

def mergeDicts(*args):
	context = {}
	for arg in args:
		context.update(arg)
	return context

def removeUnderscoreKeys(x):
	if isinstance(x, list):
		return [removeUnderscoreKeys(v) for v in x]
	elif isinstance(x, dict):
		return dict((k.replace('_', ''), removeUnderscoreKeys(v)) for k, v in x.iteritems())
	return x

def filterByDateRange(qset, request=None, start=None, kind=None, eod=0, field="created", end=None):
	"""
	"DateRangeStart": POSIX Start Date,
	"DateRangeEnd": POSIX End Date,
	"DateRangeEOD": Specify the UTC end of day for the range
	"DateRangeField": "created or modified",
	"DateRangeKind": "none, day, month, year",
	"""
	if request:
		start = request.DATA.get("daterangestart", start)
		if not start:
			return qset

		start = parseDate(start)
		eod = request.DATA.get("daterangeeod", eod, field_type=int)
		if not eod and request.group:
			eod = request.group.getEOD(onday=start)
		end = request.DATA.get("daterangeend", end)
		if end is None:
			end = start + timedelta(days=1)
		else:
			end = parseDate(end)

		if end <= start:
			end = start + timedelta(days=1)
		print "field is: {}".format(field)
		field = request.DATA.get("daterangefield", field)
		print "field is: {}".format(field)
		kind = request.DATA.get("daterangekind", kind)
		# print eod
		start, end = getDateRange(start=start, end=end, kind=kind, eod=eod)
		# print start
		# print end
	else:
		start, end = getDateRange(start=start, end=None, kind=kind, eod=eod)

	if not field:
		field = "created"

	qf = {"{0}__gte".format(field):start, "{0}__lte".format(field):end}
	return qset.filter(**qf)




def diffMinutes(t1, t2):
    diff = t1 - t2
    days, seconds = diff.days, diff.seconds
    hours = (days * 24)
    return (seconds * 60) + (hours / 60)

def diffHours(t1, t2):
    diff = t1 - t2
    days, seconds = diff.days, diff.seconds
    hours = (days * 24)
    minutes = seconds * 60
    return (minutes * 60) + hours

def getContext(request, *args, **kwargs):
	version = settings.VERSION
	if settings.DEBUG:
		version = "{0}.{1}".format(version, time.time())

	c = {
		"version":version,
		"SITE_LABEL":settings.SITE_LABEL,
		"SERVER_NAME":settings.SERVER_NAME,
		"SHARE_HOST":settings.SHARE_HOST,
		"TWITTER_HANDLE":settings.TWITTER_HANDLE,
		"settings":settings,
		"BASE_URL":settings.BASE_URL
	}

	if request:
		c["protocol"] = getProtocol(request)
		c["request"] = request

	for k, v in kwargs.iteritems():
		c[k] = v
	return c

def getAppNames():
	from django.apps import apps
	return [app_config.name for app_config in apps.get_app_configs()]

def getAllModels(app_name=None):
	from django.apps import apps
	if not app_name:
		return apps.get_models()
	return apps.get_app_config(app_name).get_models()


def find_nth(haystack, needle, n):
	start = haystack.find(needle)
	while start >= 0 and n > 1:
		start = haystack.find(needle, start+len(needle))
		n -= 1
	return start


def getSetting(key, default=None):
	if hasattr(settings, key):
		return getattr(settings, key)
	return default

def filterByDates(qset, start=None, end=None, date_field="created"):
	q = {}
	if start:
		q["{}__gte".format(date_field)] = start

	if end:
		q["{}__lte".format(date_field)] = end
	if q:
		return qset.filter(**q)
	return qset

def getAverage(qset, field_name):
	res = qset.aggregate(avg_result=Avg(field_name))
	if res.has_key("avg_result") and res["avg_result"] != None:
		return res["avg_result"]
	return 0.0

def getMin(qset, field_name):
	res = qset.aggregate(max_result=Min(field_name))
	if res.has_key("min_result") and res["min_result"] != None:
		return res["min_result"]
	return 0.0

def getMax(qset, field_name):
	res = qset.aggregate(max_result=Max(field_name))
	if res.has_key("max_result") and res["max_result"] != None:
		return res["max_result"]
	return 0.0

def getSum(qset, *args):
	params = {}
	for field_name in args:
		key = "sum_{}".format(field_name)
		params[key] = Sum(field_name)
	# print params
	res = qset.aggregate(**params)

	results = UberDict()
	for field_name in args:
		key = "sum_{}".format(field_name)
		value = res.get(key, 0)
		if value is None:
			value = 0
		results[field_name] = value
	if len(args) == 1:
		return results.values()[0]
	return results

_KEY_NOTFOUND = object()

def getValueForKeys(data, key, default=None):
	# helper method for getting first key value from list
	if type(key) is list:
		for k in key:
			v = getValueForKeys(data, k, _KEY_NOTFOUND)
			if v != _KEY_NOTFOUND:
				return v
		return default

	if "." in key:
		keys = key.split('.')
		for k in keys:
			data = getValueForKeys(data, k, _KEY_NOTFOUND)
			if data is _KEY_NOTFOUND:
				return default
		return data

	if data is None:
		return None
	return data.get(key, default)

def dictToString(d):
	from StringIO import StringIO
	output = StringIO()
	prettyWrite(d, output)
	out = output.getvalue()
	output.close()
	return out

def prettyPrint(d, f=sys.stdout, indent=4, banner=None):
	return prettyWrite(d, f, indent, banner)


try:
	import phonenumbers
except:
	phonenumbers = None

def isPhone(value):
	try:
		int(value.replace('-', '').replace('.', '').replace(' ', ''))
		return True
	except:
		pass
	return False

def normalizePhone(value):
	if phonenumbers:
		try:
			x = phonenumbers.parse(value, "US")
		except:
			print value
			x = phonenumbers.parse(value, None)
		return phonenumbers.format_number(x, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
	return value.replace(' ', '').replace('.', '-').replace('(', '').replace(')', '-')


from decimal import Decimal
PRETTY_INDENT = 2
PRETTY_MAX_VALUE_LENGTH = 200
PRETTY_MAX_LINES = 160
PRETTY_MAX_LENGTH = 5000

def prettyWrite(d, f=None, indent=PRETTY_INDENT, banner=None, line_count=0):
	std_output = False
	if f is None:
		std_output = True
		f = StringIO()

	prev = None
	if banner:
		f.write('---- BEGIN {} ----\n'.format(banner))
	if type(d) is list:
		prev = False
		f.write('[')
		for i in d:
			if prev:
				line_count += 1
				f.write(',\n')
			else:
				line_count += 1
				f.write('\n')

			pos = 0
			if hasattr(f, "len"):
				pos = f.len

			if line_count > PRETTY_MAX_LINES or pos >= PRETTY_MAX_LENGTH:
				f.write(u'{}"...truncated"'.format(' ' * indent))
				break
			prev = True
			if type(i) is bool:
				i = int(i)
			if type(i) in [unicode, str]:
				if len(i) >= PRETTY_MAX_VALUE_LENGTH:
					f.write(u'{}"{}...truncated"'.format(' ' * indent, i[:PRETTY_MAX_VALUE_LENGTH-20]))
				else:
					f.write(u'{}"{}"'.format(' ' * indent, i))
			elif type(i) is list or isinstance(i, dict):
				f.write(' ' * (indent))
				line_count = prettyWrite(i, f, indent+PRETTY_INDENT, line_count=line_count)
			elif type(i) is Decimal:
				f.write('{}{}'.format(' ' * indent, str(i)))
			else:
				f.write(u'{}"{}"'.format(' ' * indent, i))
		line_count += 1
		f.write('\n')
		f.write(' ' * (indent-PRETTY_INDENT))
		f.write(']')
	elif isinstance(d, dict):
		f.write('{')
		for key, value in d.iteritems():
			if prev:
				line_count += 1
				f.write(',\n')
			else:
				line_count += 1
				f.write('\n')

			pos = 0
			if hasattr(f, "len"):
				pos = f.len

			if line_count > PRETTY_MAX_LINES or pos >= PRETTY_MAX_LENGTH:
				f.write('{}"truncated":"...truncated"\n'.format(' ' * indent))
				break
			prev = True
			if type(key) in [unicode, str]:
				f.write('{}"{}":'.format(' ' * indent, key))
			else:
				f.write('{}{}: '.format(' ' * indent, str(key)))
			if type(value) is list or isinstance(value, dict):
				f.write(' ')
				line_count = prettyWrite(value, f, indent+PRETTY_INDENT, line_count=line_count)
			else:
				if type(value) in [unicode, str]:
					if len(value) >= PRETTY_MAX_VALUE_LENGTH:
						f.write(u' "{}...truncated"'.format(value[:PRETTY_MAX_VALUE_LENGTH-20]))
					else:
						f.write(u' "{}"'.format(value))
				elif type(value) in [datetime, time]:
					f.write(' "{}"'.format(value))
				elif type(value) is Decimal:
					f.write(' {}'.format(str(value)))
				else:
					f.write(u' {}'.format(value))
		line_count += 1
		f.write('\n')
		f.write(' ' * (indent-PRETTY_INDENT))
		f.write('}')
	else:
		f.write(str(d))

	if banner:
		f.write('\n---- END {} ----\n'.format(banner))
	if indent == PRETTY_INDENT:
		f.write("\n")
	if std_output:
		sys.stdout.write(f.getvalue())
		f.close()
	return line_count

def randomKey(count=6):
	return ''.join(random.choice(string.uppercase + string.digits) for x in range(count))

def getStackString():
	import traceback
	return str(traceback.format_exc())
