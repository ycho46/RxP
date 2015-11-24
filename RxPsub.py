import ctypes
import math
from functools import reduce

class myException(Exception):
	"""Exception that gives details on RxP related errors."""

	# exception types

	# checksums do not match
	INVALID_CHECKSUM = 1
	# packet sent from outside
	# connection
	OUTSIDE_PACKET = 2
	# connection timed out
	CONNECTION_TIMEOUT = 3
	# packet type not expected
	# SYN, ACK, etc
	UNEXPECTED_PACKET = 4
	# mismatch between packet seq
	# num and expected seq num
	SEQ_MISMATCH = 5
	# Maximum resend limit reached
	RESEND_LIM = 6

	DEFAULT_MSG = {
		INVALID_CHECKSUM: "invalid checksum",
		OUTSIDE_PACKET: "outside packet",
		CONNECTION_TIMEOUT: "connection timeout",
		UNEXPECTED_PACKET: "unexpected packet type",
		SEQ_MISMATCH: "sequence mismatch",
		RESEND_LIM: "Maximum reset limit reached"
	}

	def __init__(self, type_, msg=None, innerException=None):
		self.type = type_
		self.inner = innerException
		if msg is None:
			self.msg = myException.DEFAULT_MSG[type_]
		else:
			self.msg = msg

	def __str__(self):
		return self.msg


class Connection:
	"""enum that describes the status 
	of a connection
	"""
	NOT_ESTABLISHED = "not established"
	IDLE = "Idle"
	SENDING = "Sending"
	RECEVING = "Receiving"

class PacketComponents:
	"""class for creating the bit string sets the 
	type of the packet being sent.
	"""

	# possible components
	_values = ["SYN", "CLOSE", "CONF","B", "E",  
		"ACK", "NOP", "SRQ", "FIN"] 

	@staticmethod
	def pickle(comp=None):
		"""produces a single byte string with the
		correct bit set for each pack type passed
		in as a string.
		"""
		if comp is None:
			submittedComps = ()
		else:
			submittedComps = list(comp)
			
		compList = []
		pos = 0

		# add components to list if they match
		# an component offered in __values
		for item in PacketComponents._values:
			if item in submittedComps:
				byte = 0b1 << pos
				compList.append(byte)
			pos += 1

		# generate binary from array
		if len(submittedComps) > 0:
			if len(compList) > 1:
				byteStr = reduce(lambda x,y: x | y,compList)
			else:
				byteStr = compList[0]
		else:
			byteStr = 0
		
		return byteStr

	@staticmethod
	def unpickle(byteStr):
		"""creates an instance of PacketComponents from
		a pickled instance (byte string)
		"""
		comp = list()
		pos = 0

		# check each bit in the byte string
		for item in PacketComponents._values: 
			if (byteStr >> pos & 1):
				comp.append(item)
			pos += 1

		return tuple(comp)

	def __str__(self):
		return repr(self.comp)

class Header:
	"""Encapsulation of the header fields
	associated with a packet. See API docs
	for descriptions of each header field.
	"""

	# define binary types for use in header fields.
	uint16 = ctypes.c_uint16
	uint32 = ctypes.c_uint32

	# available header fields. formatted as:
	# fieldName, dataType, numBytes
	FIELDS = (
		("srcPort", uint16, 2),
		("destPort", uint16, 2),
		("seq", uint32, 4),
		("ack", uint32, 4),
		("rWindow", uint16, 2),
		("length", uint16, 2),
		("checksum", uint16, 2),
		("comp", uint32, 4)
		)

	# sum of the length of all fields (bytes)
	LENGTH = sum(map(lambda x: x[2], FIELDS))

	def __init__(self, **kwargs):
		self.fields = {}
		keys = kwargs.keys()

		for item in Header.FIELDS:
			fieldName = item[0]
			fieldType = item[1]
			if fieldName in keys:
				field = kwargs[fieldName]
			else:
				field = 0
			self.fields[fieldName] = field

	def pickle(self):
		"""converts the object to a binary string
		that can be prepended onto a packet. pickle
		enforces size restrictions and pads fields
		"""
		byteArr = bytearray()

		# add fields to bytearray one field at a time
		for item in Header.FIELDS:
			# print ('itme',item)
			fieldName = item[0]
			fieldType = item[1]
			fieldVal = self.fields[fieldName]
			# print (fieldVal,'fieldVal')
			if fieldVal is not None:
				# print (bytearray(fieldType(fieldVal)))
				byteArr.extend(bytearray(fieldType(fieldVal)))
				# print (byteArr)

		return byteArr

	@staticmethod
	def unpickle(byteArr):
		"""creates an instance of Header from a byte
		array. This must be done manually using knowledge
		about the order and size of each field.
		"""

		# ensure the byte array is of
		# type bytearray
		if not isinstance(byteArr, bytearray):
			byteArr = bytearray(byteArr)

		h = Header()
		base = 0
		for item in Header.FIELDS:

			fieldName = item[0]
			fieldType = item[1]
			fieldSize = item[2]

			# extract field from header using
			# base + offset addressing
			value = byteArr[base : base + fieldSize]

			# convert value from bytes to int
			field = fieldType.from_buffer(value).value

			# update base
			base += fieldSize

			# add field to header 
			h.fields[fieldName] = field

		return h

	def __str__(self):
		
		str_ = "{ "
		for item in Header.FIELDS:
			fieldName = item[0]
			if fieldName in self.fields:
				str_ += fieldName + ': ' 
				if fieldName == "comp":
					str_ += repr(PacketComponents.unpickle(
						self.fields[fieldName]))
				else:
					str_ += str(self.fields[fieldName]) + ', '
		str_ += " }"

		return str_


class Packet:
	"""Represents a single packet and includes
	header and data.
	"""

	# maximum sequence number
	MAX_SEQ_NUM = math.pow(2, 32)
	# max window size for sender
	# or receiver (bytes)
	MAX_WINDOW_SIZE = 65485
	# Ethernet MTU (1500) - UDP header
	DATA_LENGTH = 3 #1000
	STRING_ENCODING = 'UTF-8'

	def __init__(self, header=None, data=""):

		if len(data) > Packet.DATA_LENGTH:
			self.data = data[0:Packet.DATA_LENGTH-1]
		else:
			self.data = data
		self.header = header or Header()
		self.header.fields["length"] = len(data)
		self.header.fields["checksum"] = self._checksum()


	def pickle(self):
		""" returns a byte string representation
		using pickling"""

		b = bytearray()
		# print (b,'byte arrrr')
		b.extend(self.header.pickle())

		if isinstance(self.data, str):
			b.extend(self.data.encode(
				encoding=Packet.STRING_ENCODING))
		elif (isinstance(self.data, bytearray)
			or isinstance(self.data, bytes)):
			b.extend(self.data)

		return b

	@staticmethod
	def unpickle(byteArr, toString=False):
		""" returns an instance of Packet
		reconstructed from a byte string.
		"""
		p = Packet()

		p.header = Header.unpickle(
			byteArr[0:Header.LENGTH])

		if toString:
			p.data = byteArr[Header.LENGTH:].decode(
				encoding=Packet.STRING_ENCODING)
		else:
			p.data = byteArr[Header.LENGTH:]

		return p

	# http://stackoverflow.com/a/1769267
	@staticmethod
	def _add(a, b):
	    c = a + b
	    return (c & 0xffff) + (c >> 16)

	# http://stackoverflow.com/a/1769267
	def _checksum(self):
		self.header.fields["checksum"] = 0
		p = str(self.pickle())
		# print (p)

		s = 0
		for i in range(0, len(p)-1, 2):
		    w = ord(p[i]) + (ord(p[i+1]) << 8)
		    s = Packet._add(s, w)
		s = ~s & 0xffff

		return s

	def verify(self):
		# compare packet checksum with
		# calculated checksum
		packetChksum = self.header.fields["checksum"]
		calcChksum = self._checksum()
		self.header.fields["checksum"] = packetChksum

		return packetChksum == calcChksum

	def checkComp(self, expectedComp, exclusive=False):
		# verify expected comp
		comp = PacketComponents.unpickle(
			self.header.fields["comp"])

		if (exclusive and 
			len(comp) != len(expectedComp)):
			return False
		else:
			for attr in expectedComp:
				if (attr is not None and 
					attr not in comp):
					return False
		return True
			

	def __str__(self):
		d = self.__dict__ 
		d2 = {}
		for key in d.keys():
			d2[key] = str(d[key])
		return str(d2)

class counter:
	""" class that is used for counting .
	when the count reaches the max value, it wraps around to
	zero.
	"""

	def __init__(self, initial=0, step=1, max=0):
		self.max = max
		self.step = step
		self.num = initial

	def reset(self, value=None):
		if value is None:
			initial = random.randint(0, Packet.MAX_SEQ_NUM)
			self.num = initial
		else:
			self.num = value

	def next(self):
		# wrap around if max 
		# has been reached
		self.num += self.step
		if self.num > self.max:
			self.num = 0
		return self.num	

	def __str__(self):
		return str(self.num)
