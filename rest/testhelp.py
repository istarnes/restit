import requests
import json
import sys
import time
import datetime
import uuid
import urllib
import pprint
from .models import UberDict
import traceback
import linecache
pp = pprint.PrettyPrinter(indent=4)

from rest.models import get_model
from rest.views import restList, restGet
from rest import helpers
from auditlog.models import ConsoleColors
from rest.RequestData import RequestData
from StringIO import StringIO
from django.core.handlers.wsgi import WSGIRequest

class TestSuiteFailed(Exception):
    def __init__(self, msg, code=0, pcode=None):
    	self.msg = msg
    	self.message = msg
    	self.code = code
    	self.pcode = pcode

def fake_request(method="GET", path='/', user=None):
    req = WSGIRequest({
            'REQUEST_METHOD': method,
            'PATH_INFO': path,
            'wsgi.input': StringIO()})
    from django.contrib.auth.models import AnonymousUser
    req.user = AnonymousUser() if user is None else user
    return req


def lower_keys(x):
	if isinstance(x, list):
	  return [lower_keys(v) for v in x]
	elif isinstance(x, dict):
	  return UberDict(dict((k.lower(), lower_keys(v)) for k, v in x.iteritems()))
	else:
	  return x

def processResponse(res, url):
	if res.status_code != 200:
		if res.status_code == 404:
			return None,"{0} NOT FOUND".format(url)
		return None, "server error"

	try:
		data = lower_keys(res.json())
		# if data.has_key("status") and not data.get("status"):
		# 	if data.has_key("error"):
		# 		return None, "SERVER: " + data.get("error")
		# 	return None, "SERVER: status false no message"
		return data, None
	except Exception as err:
		return None, str(err)
	return None

def POST(host, path, data, post_json=False, session=None):
	url = "{0}/{1}".format(host, path)
	headers = {'Accept': 'application/json'}
	if post_json:
		data = json.dumps(data)
		headers['Content-type'] = 'application/json'
	if session:
		res = session.post(url, data=data, headers=headers)
	else:
		res = requests.post(url, data=data, headers=headers)
	return processResponse(res, url)

def GET(host, path, data=None, session=None):
	url = "{0}/{1}".format(host, path)
	if data:
		url = "{0}?{1}".format(url, urllib.urlencode(data))
	headers = {'Accept': 'application/json'}
	if session:
		res = session.get(url, headers=headers)
	else:
		res = requests.get(url, headers=headers)
	return processResponse(res, url)

def testAssert(exp, fail_msg=None):
	assert exp, fail_msg

def expectAssert(exp, got, name):
	assert exp==got, "{0} expected '{1}' but got '{2}'".format(name, exp, got)


class _AssertRaisesContext(object):
	"""A context manager used to implement assertRaises* methods."""

	def __init__(self, expected, test_case):
		self.expected = expected
		self.failureException = None

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, tb):
		if exc_type is None:
			try:
				exc_name = self.expected.__name__
			except AttributeError:
				exc_name = str(self.expected)
			raise AssertionError("{0} not raised".format(exc_name))
		if not issubclass(exc_type, self.expected):
			# let unexpected exceptions pass through
			return False
		self.exception = exc_value # store for later
		return True

class TestBase(object):
	"""
	example usage:
		self.test("login", username=TEST_USER, password=TEST_PASS)
		self.testFail("lastTrans", track=BUG_0001["Track"])
	"""
	def __init__(self, host, token=None, oid=None, verbose=False, extra=None, name=None):
		self.host = host
		self.token = token
		self.terminal_id = oid
		self.session = None
		self.post_json = True
		self.verbose = verbose
		self.last_res = None
		self.username = None
		self._user = None
		self._terminal = None
		self.name = name


	def assertTrue(self, exp, fail_msg=None):
		assert exp, fail_msg

	def assertFalse(self, exp, fail_msg=None):
		assert not exp, fail_msg

	def assertIs(self, obj1, obj2):
		class1_name = obj1.__class__.__name__
		if obj2 != None:
			class2_name = obj2.__class__.__name__
		else:
			class2_name = "None"
			
		assert obj1 is obj2, "{} is not {}".format(class1_name, class2_name)

	def assertNotEqual(self, exp, got, name=""):
		assert exp!=got, "{0} expected '{1}' != '{2}'".format(name, exp, got)

	def assertEqual(self, exp, got, name=""):
		assert exp==got, "{0} expected '{1}' == '{2}'".format(name, exp, got)

	def assertEqualToDict(self, obj, dic):
		"""
		Will take all the items and the dic and compare them
		to items in the obj or dict
		"""
		class_name = obj.__class__.__name__
		for key, value in dic.items():
			if not hasattr(obj, key):
				raise AssertionError("{0}.{1} not found".format(class_name, key) )
			obj_value = getattr(obj, key)
			if isinstance(obj_value, datetime.datetime):
				obj_value = time.mktime(obj_value.timetuple())
			elif isinstance(obj_value, datetime.date):
				obj_value = obj_value.strftime("%Y/%m/%d")
			if obj_value != value:
				raise AssertionError("{0}.{1} expected {2} == {3}".format(class_name, key, obj_value, value) )
		return True

	def assertNotHasKeys(self, obj, keys, not_null=False):
		if type(keys) in [str, unicode]:
			keys = [keys]
		class_name = obj.__class__.__name__
		for key in keys:
			has_key = obj.has_key(key)
			assert not has_key, "{0}.{1} found".format(class_name, key)

	def assertHasKeys(self, obj, keys, not_null=False):
		if not hasattr(obj, "has_key"):
			return self.assertHasAttrs(obj, keys, not_null)
		if type(keys) in [str, unicode]:
			keys = [keys]
		class_name = obj.__class__.__name__
		for key in keys:
			has_key = obj.has_key(key)
			if has_key and not_null:
				assert obj.get(key) != None, "{0}.{1} is None".format(class_name, key)
			assert has_key, "{0}.{1} not found".format(class_name, key)

	def assertHasAttrs(self, obj, attrs, not_null=False):
		if hasattr(obj, "has_key"):
			return self.assertHasKeys(obj, attrs, not_null)
		if type(attrs) in [str, unicode]:
			attrs = [attrs]
		class_name = obj.__class__.__name__
		for attr in attrs:
			has_attr = hasattr(obj, attr)
			if has_attr and not_null:
				assert getattr(obj, attr) != None, "{0}.{1} is None".format(class_name, attr)
			assert has_attr, "{0}.{1} not found".format(class_name, attr)


	def assertRaises(self, excClass):
		return _AssertRaisesContext(excClass, self)

	def assertRestError(self, res, err_code):
		msg = "expected error_code"
		assert res.has_key("error_code"), msg
		self.assertEqual(err_code, res.error_code, "error_code")

	def fail(self, fail_msg=None):
		raise AssertionError(fail_msg)

	def fakePassword(self):
		return str(uuid.uuid1())

	def createFakeUser(self, username, pword, group=None, role=None):
		Member = self.getModel("account", "Member")
		member = Member.objects.filter(username=username).last()
		if member is None:
			member = Member(username=username, email="ian+{}@311labs.com", first_name="Test", last_name=username)
			member.save()
		member.setPassword(pword)
		member.save()
		if group:
			if not member.isMemberOf(group):
				group.addMembership(member, role)
		return member

	def createFakeRequest(self, method="GET", path="", user=None, data=None):
		if not self._user and self.username:
			Member = self.getModel("account", "Member")
			self._user = Member.objects.filter(username=self.username).last()
		request = fake_request(method, path, self._user)
		request.member = self._user
		request.session = self.session
		if not self._terminal and self.token:
			Terminal = self.getModel("payauth", "Terminal")
			self._terminal = Terminal.objects.filter(token=self.token).last()
		request.terminal = self._terminal
		if request.terminal:
			request.merchant = request.terminal.merchant
			request.group = request.merchant
		data = UberDict() if data is None else data
		RequestData.upgradeRequest(request, data)
		return request
	
	def getModel(self, app_name, model_name):
		return get_model(app_name, model_name)

	def modelToDict(self, model, graph):
		request = self.createFakeRequest()
		return restGet(request, model, return_httpresponse=False, **model.__class__.getGraph(graph))

	# expectedResult is used in MockTestBase
	def POST(self, path, data=None, expectedResult = None):
		if self.token:
			data["terminal_token"] = self.token
		if not self.session:
			self.session = requests.session()
		self.last_res = None
		res, msg = POST(self.host, path, data, self.post_json, session=self.session)
		self.last_res = res
		return res, msg

	# expectedResult is used in MockTestBase
	def GET(self, path, params={}, expectedResult = None):
		if self.token:
			params["terminaltoken"] = self.token
		if not self.session:
			self.session = requests.session()
		self.last_res = None
		res, msg = GET(self.host, path, params, session=self.session)
		self.last_res = res
		return res, msg

	def SAVE(self, path, saveto, params={}):
		if self.token:
			params["terminaltoken"] = self.token
		if self.session:
			r = self.session.get(path, stream=True)
		else:
			r = requests.get(path, stream=True)

		with open(local_filename, 'wb') as f:
			for chunk in r.iter_content(chunk_size=1024): 
				if chunk: # filter out keep-alive new chunks
					f.write(chunk)
					f.flush()
		return local_filename

	def prettyPrint(self, obj):
		print ""
		# pp.pprint(obj)
		helpers.prettyWrite(obj)

	def testFail(self, name, **kwargs):
		print "\t{0}running {1}".format(ConsoleColors.HYELLOW, name).ljust(12),
		try:
			getattr(self, name)(**kwargs)
			print "expected error but got none"
			self.clean_up(name)
			sys.exit(1)
		except AssertionError as err:
			print "success"
			self.clean_up(name)
		return True

	def test(self, name, **kwargs):
		started = time.time()
		func_name = kwargs.pop("func_name", None)
		if not func_name:
			func_name = name
		print "\t{0}running {1}{2}".format(ConsoleColors.HYELLOW, name, ConsoleColors.OFF).ljust(50),
		try:
			getattr(self, func_name)(**kwargs)
			print "{0}{1:.2f}s -- success{2}".format(ConsoleColors.HGREEN, time.time()-started, ConsoleColors.OFF)
			self.clean_up(func_name)
			return True
		except AssertionError as err:
			print "{0}{1:.2f}s -- fail {2}".format(ConsoleColors.HRED, time.time()-started, ConsoleColors.OFF)

			if self.verbose:
				exc_type, exc_obj, tb = sys.exc_info()
				tb = tb.tb_next
				f = tb.tb_frame
				lineno = tb.tb_lineno
				filename = f.f_code.co_filename
				
				linecache.checkcache(filename)
				line = linecache.getline(filename, lineno, f.f_globals)

				if self.last_res:
					print '\n-- begin response --'
					helpers.prettyPrint(self.last_res)
					print '-- end response   --'
				print ConsoleColors.RED
				print '___ assert info ___'
				print "location: {0}:{1}".format(filename, lineno)
				print ConsoleColors.OFF + ConsoleColors.HRED
				print line.strip()
				print str(err)
				print ConsoleColors.OFF + ConsoleColors.RED
				print '___ end assert ___'
				print ConsoleColors.OFF

			self.clean_up(func_name)
		except Exception as err:
			print "{0:.2f}s -- ERROR".format(time.time()-started)
			# if self.verbose:
			print "\n"
			print ConsoleColors.HRED
			print str(err)
			print '--- TRACEBACK ------'
			# traceback.print_stack()
			# print '--------------'
			traceback.print_exc()
			print ConsoleColors.OFF
			self.clean_up(func_name)
		raise TestSuiteFailed("ABORTED: A Test Failed!")

	def clean_up(self, func_name):
		pass

	def refreshToken(self, terminal_id=None):
		path = "rpc/payauth/terminal/token"
		if terminal_id:
			self.terminal_id = terminal_id
		self.assertTrue(self.terminal_id != None)
		
		data = {"terminal_id":self.terminal_id}
		res, msg = self.POST(path, data)
		self.assertTrue(res, msg)
		data = res["data"]
		self.assertHasKeys(data, ["terminal_token"])
		old_token = self.token
		self.token = data.get("terminal_token")
		self.assertNotEqual(old_token, self.token)

	def buildPost(self, **kwargs):
		data = {}
		for key, value in kwargs.iteritems():
			if value:
				data[key] = value
		return data

	def login(self, username, password):
		path = "rpc/account/login"
		params = self.buildPost(username=username, password=password)

		res, msg = self.POST(path, params)
		self.assertTrue(res, msg)

		data = res["data"]

		self.assertTrue(self.session, "session not returned")
		self.assertTrue(data.get('username')==username, "username did not match")
		self.username = username
		self.assertTrue(self.isSessionActive(), "session is not active")

	def isSessionActive(self):
		path = "rpc/account/user/me"

		res, msg = self.GET(path)
		testAssert(res, msg)
		err = res.get("error")
		if err:
			self.fail(err)
		data = res.get("data")
		return data.get('username')==self.username

	def logout(self):
		path = "rpc/account/logout"
		params = {}

		res, msg = self.POST(path, params)
		testAssert(res, msg)

		try:
			self.isSessionActive()
			raise AssertionError("session is still active!")
		except:
			pass

		self.session = False

	def verifyReturn(self, data, errmsg, expectedResult):
		# If none, we're executing the POST/GET to set up some pre-conditions.
		if (expectedResult != None):
			if (expectedResult == "fail"):
				testAssert(data == None)
				testAssert(errmsg != None)
			else:
				testAssert(data, errmsg)		# verify we didn't get None back.
				self._verifyReturn(data, expectedResult)

	def _verifyReturn(self, data, expected):
		n = 1
		for key in expected:
			testAssert(key in data, "Expected result to have key " + key)
			expectedVal = expected[key]

			if (type(expectedVal) is dict):
				# drill into child dictionaries...
				self._verifyReturn(data[key], expectedVal)
			elif (type(expectedVal) is list):
				recIdx = -1
				retVal = data[key]

				for rec in retVal:			# Iterate array.
					recIdx = recIdx + 1
					# Assumes a key-value pair dictionary for each array element.
					for key in expectedVal[recIdx]: # Iterate dictionary.
						if (rec[key]=="#"):						# Our mock testing will want this value populated with some number.
							rec[key] = n  						# Populate the expected value with incrementing number.
							n += 1
						elif (expectedVal[recIdx][key]=="#"):
							pass 								# Expected value can be anything, so no test.
						else:
							testAssert(expectedVal[recIdx][key] == rec[key])

			else:
				if (data[key] == "#"):		# Real data would not return "#", our mock expected results will want this populated with some number.
					data[key] = n
					n += 1
				elif (expectedVal == "#"):
					pass 					# Expected value can be anything, so no test.
				else:
					retVal = data[key]
					testAssert(retVal == expectedVal, "Expected value '" + str(expectedVal) + "' for key " + key)

	def run(self):
		"""
		this will run all methods prefixed with "run_" as a test
		"""
		if self.name:
			print "{}TEST: {} {}".format(ConsoleColors.HPINK, self.name.upper(), ConsoleColors.OFF)

		try:
			for func_name in dir(self):
				if func_name.startswith("run_") and hasattr(getattr(self, func_name, None), '__call__'):
					print "  {0}running {1}{2}".format(ConsoleColors.HBLUE, func_name, ConsoleColors.OFF)
					getattr(self, func_name)()
		except TestSuiteFailed as err:
			pass
			
	def quick(self):
		"""
		this will run all methods prefixed with "run_" as a test
		"""
		for func_name in dir(self):
			if func_name.startswith("quick_") and hasattr(getattr(self, func_name, None), '__call__'):
				getattr(self, func_name)()

	def example(self, amount, track=None, cardnumber=None, zipcode=None, epb=None, state=20, expires=None):
		path = "rpc/casinomoney/transaction/authorize"
		params = self.buildPost(amount=amount, track=track, expires=expires, cardnumber=cardnumber, zipcode=zipcode, epb=epb)

		res, msg = self.POST(path, params)
		testAssert(res, msg)

class MockTestBase(TestBase):
	def __init__(self, host, oid = None):
		super(MockTestBase, self).__init__(host, oid = oid)

	def refreshToken(self):
		self.token = "12349876"

	def POST(self, path, data=None, expectedResult = None):
		self.last_res = "ok"
		if (expectedResult == "fail"):
			return None, "Error"
		else:
			return expectedResult, None

	def GET(self, path, data=None, expectedResult = None):
		self.last_res = "ok"
		if (expectedResult == "fail"):
			return None, "Error"
		else:
			return expectedResult, None

