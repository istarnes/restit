from django.template.loader import render_to_string

from django.template import TemplateDoesNotExist
from django.template import RequestContext
from django.core.mail import EmailMultiAlternatives

from inlinestyler.utils import inline_css
from smtplib import SMTPException
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.conf import settings

# DISABLE crazy error logging
import sys
import logging
import cssutils
cssutils.log.setLevel(logging.CRITICAL)


import threading
import StringIO
import csv

from rest.middleware import get_request

def generateCSV(qset, fields, name):
	a = UberDict()
	a.name = name
	a.file = StringIO.StringIO()
	csvwriter = csv.writer(a.file)
	csvwriter.writerow(fields)

	for row in qset.values_list(*fields):
		row = [unicode(x) for x in row]
		csvwriter.writerow(row)
	a.data = a.file.getvalue()
	a.mimetype = "text/csv"
	return a

def send(to, subject, body=None, attachments=[], from_email=settings.DEFAULT_FROM_EMAIL, fail_silently=True, template=None, context=None, async=False):
	if type(to) not in (tuple, list):
		to = [to]

	if template and body and not context:
		context = {
			"body":body
		}

	if template and context:
		if type(context) is dict:
			context['settings'] = settings
		body = render_to_string(template, context)
		body = inline_css(body)

	msg = EmailMessage(subject=subject, body=body, from_email=from_email, to=to)
	msg.content_subtype = "html"
	for a in attachments:
		if type(a) in [str, unicode]:
			msg.attach_file(a)
		else:
			msg.attach(a.name, a.data, a.mimetype)

	if async:
		t = threading.Thread(target=async_send, args=[msg])
		t.start()
	else:
		msg.send(fail_silently=fail_silently)


def sendToSupport(subject, body=None, attachments=[], from_email=settings.DEFAULT_FROM_EMAIL, fail_silently=True, template="email/base.html", context=None, async=True):
	send(settings.ADMIN_NOTIFY_USERS, subject, body=body, attachments=attachments, from_email=from_email, fail_silently=fail_silently, template=template, context=context, async=async)

def async_send(email, attempts=0):
	try:
		email.send()
	except Exception, e:
		msg = str(e)
		print "Error sending email: %s: %s" % (type(e).__name__, msg)
		if attempts==0 and "try again" in msg.lower():
			time.sleep(1.0)
			async_send(email, attempts+1)
		else:
			logging.getLogger("app").error("Error sending email: %s: %s" % (type(e).__name__, str(e)))
	
def render_to_mail(name, context):
	if not context.get("request"):
		context["request"] = get_request()
	# if not isinstance(context, RequestContext):
	# 	tmp = RequestContext(context.get('request', None))
	# 	tmp.update(context)
	# 	context = tmp
	context['newline'] = "\n"
	# print "TEMPLATE NAME: {0}".format(name)
	if 'to' in context:
		toaddrs = context['to']
		if type(toaddrs) != list:
			toaddrs = [toaddrs]
	else:
		try:
			toaddrs = render_to_string(name + ".to", context).splitlines()
		except TemplateDoesNotExist as err:
			return
	try:
		while True:
			toaddrs.remove('')
	except ValueError:
		pass
	if len(toaddrs) == 0:
		logging.getLogger("app").error("Sending email to no one: %s" % name)
		return

	try:
		html_content = render_to_string(name + ".html", context)
		html_content = inline_css(html_content)
	except TemplateDoesNotExist as err:
		html_content = None
		pass

	text_content = ""
	try:
		text_content = render_to_string(name + ".txt", context)
	except TemplateDoesNotExist as error:
		if html_content == None:
			raise TemplateDoesNotExist("requires at least one content template")

	if 'from' in context:
		fromaddr = context['from']
	else:
		try:
			fromaddr = render_to_string(name + ".from", context).rstrip()
		except TemplateDoesNotExist:
			fromaddr = settings.DEFAULT_FROM_EMAIL
	# print fromaddr
	if 'subject' in context:
		subject = context['subject']
	else:
		try:
			subject = render_to_string(name + ".subject", context).rstrip()
		except TemplateDoesNotExist:
			logging.getLogger("app").error("Sending email without subject: %s" % name)
			return False
	headers = None
	if "replyto" in context:
		headers={'Reply-To': context["replyto"]}

	email = EmailMultiAlternatives(subject, text_content, fromaddr, toaddrs, headers=headers)
	if html_content:
		email.attach_alternative(html_content, "text/html")
	print "sending email to: {0} - {1}".format(toaddrs, subject)
	logging.getLogger("debug").info("sending email to: {0} - {1}".format(toaddrs, subject))
	#try:
	t = threading.Thread(target=async_send, args=[email])
	t.start()
	# email.send()
	#except Exception, e:
	#	logging.getLogger("exception").error("Error sending email: %s: %s" % (type(e).__name__, str(e)))
	#	pass

