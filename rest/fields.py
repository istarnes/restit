
from django.db import models
from django.forms.widgets import ClearableFileInput
from django.core.files.uploadedfile import UploadedFile
from django.core import validators
from django.utils.encoding import smart_unicode

from .views import chunkUploadedFile

import re
from datetime import datetime, date

try:
	import phonenumbers
except:
	phonenumbers = None

class ResumableFileInput(ClearableFileInput):
	def value_from_datadict(self, data, files, name):
		upload = super(ResumableFileInput, self).value_from_datadict(data, files, name)
		if not upload:
			if data.has_key(name + '.path') and data.has_key(name + '.name') and data.has_key(name + '.content_type') and data.has_key(name + '.size'):
				try:
					f = open(data.get(name + '.path'))
				except OSError:
					pass
				else:
					upload = UploadedFile(file=f, name=data.get(name + '.name'), content_type=data.get(name + '.content_type'), size=data.get(name + '.size'))
		if not upload:
			if data.has_key(name + '_sessionid'):
				try:
					upload = chunkUploadedFile(data.get('__request'), data.get(name + '_sessionid'))
				except OSError:
					pass

		if upload:
			files[name] = upload
		return upload

class DateField(models.DateField):
	def to_python(self, value):
		if value == None or value == '':
			return None
		elif type(value) in (int,float):
			return date.fromtimestamp(value)
		elif type(value) in (str,unicode) and re.match('^-?[0-9]+$', value):
			try:
				return date.fromtimestamp(int(value))
			except:
				pass
		if type(value) is datetime:
			return value.date()
		return super(models.DateField, self).to_python(value)

class DateTimeField(models.DateTimeField):
	def to_python(self, value):
		if value == None or value == '':
			return None
		elif type(value) in (int,float):
			return datetime.fromtimestamp(value)
		elif type(value) in (str,unicode) and re.match('^-?[0-9]+$', value):
			try:
				return datetime.fromtimestamp(int(value))
			except:
				pass
		return super(models.DateTimeField, self).to_python(value)

from decimal import Decimal
class CurrencyField(models.DecimalField):
	def __init__(self, *args, **kwargs):
		default_value = kwargs.pop("default", 0.0)
		kwargs["default"] = default_value
		
		max_digits = kwargs.pop("max_digits", 12)
		kwargs["max_digits"] = max_digits

		decimal_places = kwargs.pop("decimal_places", 2)
		kwargs["decimal_places"] = decimal_places

		super(CurrencyField, self).__init__(*args, **kwargs)

	def from_db_value(self, value, expression, connection, context):
		if value is None:
			return value
		if not isinstance(value, Decimal):
			value = Decimal(value)
		return value.quantize(Decimal("0.01"))

	def to_python(self, value):
		if value is None:
			return value
		if not isinstance(value, Decimal):
			value = Decimal(value)
		return value.quantize(Decimal("0.01"))

class FormattedField(models.CharField):
	TITLE = 1
	UPPERCASE = 2
	LOWERCASE = 3
	PHONE = 5

	def __init__(self, *args, **kwargs):
		self.format_kind = kwargs.pop('format', 0)
		max_length = kwargs.pop('max_length', 254)
		kwargs["max_length"] = max_length
		super(FormattedField, self).__init__(*args, **kwargs)

	def from_db_value(self, value, expression, connection, context):
		return FormattedField.format(value, self.format_kind)

	def to_python(self, value):
		return FormattedField.format(value, self.format_kind)

	def get_prep_value(self, value):
		value = super(FormattedField, self).get_prep_value(value)
		return FormattedField.format(value, self.format_kind)

	@staticmethod
	def parsePhone(value, region):
		try:
			pp = phonenumbers.parse(value, region)
		except:
			return None
		return pp

	@staticmethod
	def format(value, format=0):
		if not value:
			return value
		if format == FormattedField.UPPERCASE:
			return value.upper()
		elif format == FormattedField.LOWERCASE:
			return value.lower()
		elif format == FormattedField.TITLE:
			return value.title()
		elif format == FormattedField.PHONE:
			if phonenumbers:
				try:
					x = phonenumbers.parse(value, "US")
					if not x:
						x = phonenumbers.parse(value, None)
					if not x:
						return value.replace(' ', '').replace('.', '-').replace('(', '').replace(')', '-')
					return phonenumbers.format_number(x, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
				except Exception as err:
					print err
			else:
				return value.replace(' ', '').replace('.', '-').replace('(', '').replace(')', '-')
		return value

class CommaSeparatedListField(models.Field):
	def __init__(self, max_items=None, min_items=None, *args, **kwargs):
		self.max_items, self.min_items = max_items, min_items
		super(CommaSeparatedListField, self).__init__(*args, **kwargs)
		if min_items is not None:
			self.validators.append(validators.MinLengthValidator(min_items))
		if max_items is not None:
			self.validators.append(validators.MaxLengthValidator(max_items))
				
	def to_python(self, value):
		if value in validators.EMPTY_VALUES:
			return []
		
		if type(value) in (str, unicode):
			value = value.split(',')

		ret = []
		for t in value:
			t = t.strip()
			if t:
				ret.append(smart_unicode(t))

		return ret
