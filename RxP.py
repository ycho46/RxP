import ctypes
import sys
import socket 
import math 
import struct
import logging
from collections import OrderedDict
from collections import deque
from sys import getsizeof
import random
from functools import reduce
import md5

class Zocket:
	"""Zocket is the main protocol that hold all API methods for bind(), connect(), send(), recieve(), and close()."""


	def __init__(self):
		# UDP socket
		self._socket = socket.societ(socket.AF_INET, socket.SOCK_DGRAM)
		# destAddr (ip, port)
		self.destAddr = None
		# srcAddr (port)
		self.srcAddr = None
		# sequence number
		self.seq = WrapableNum(max=Packet.MAX_SEQ_NUM)
		# ack number
		self.ack = WrapableNum(max=Packet.MAX_SEQ_NUM)
		# sender or receiver
		self.isSender = False
		# number of times to resend a packet
		self.retries = 50
		# no timeout
		self.timeout = None
		# current connection status
		self.connection = Connection.NOT_ESTABLISHED


	def bind(self, srcAddr):
		"""
		binds zocket's srcAddr and binds to input port.
		if no port is given throws an exception
		"""
		if srcAddr:
			self.srcAddr = srcAddr
			self._socket.bind(srcAddr)
		else:
			raise myException("Missing source address")
	
	def connect(self, destAddr):
		"""
		initiates connection with in input destAddr(ip,port)
		Connects using 4-way handshake.
		1. sender sends SYN packet.
		2. receiver receives SYN then sends hashed SYN,ACK
		3. sender verifies it and sends hashed ACK and establishes
		4. host receives ACK and establishes connection
		"""

		# set destAddr
		self.destAddr = destAddr

		# set SYN
		self.seq.reset(0)

		# send SYN and and verify SYN,ACK upon receiving 
		synAck = self._sendSYN()

		# set ACK
		ack = synAck.header.fields["seq"]
		self.ack.reset(ack + 1)

		# send hashed ACK
		self._sendACK()

		# connection established
		self.connection = Connection.IDLE

		# set to be sender
		self.isSender = True

	def accept(self):
		"""
		The receiver side of 4-way handshake
		"""

		#set seq number
		self.seq.reset(0)

		# sends hashed SYNACK and receive hashed ACK
		packet = self._sendSYNACK()

		# checks ACK
		if self._recvACK():
			# update connection status
			self.connection = Connection.IDLE

			# set to receiver
			self.isSender = False
		else:
			raise myException.("Wrong ACK")

	def _sendSYN(self):

		#create SYN packet
		comp = PacketComponents.pickle(("SYN",))
		header = Header(srcPort=self.srcAddr[1],
			destPort=self.destAddr[1],seq=self.seq.num,
			recvWindow=self.recvWindow, comp=comp)
		packet = Packet(header)
		self.seq.next()

		#set number of retries to try sending and receiving SYN,ACK
		numRetries = self.retries
		while numRetries:
			# send SYN
			self.sendto(packet,self.destAddr)

			try:
				data, addr = self.recvfrom(self.recvWindow)
				packet = self._packet(data=data, addr=addr, checkSeq=False)
			except socket.timeout:
				numRetries -=1
			except myException as e:
				if(e.type = myException.INVALID_CHECKSUM):
					continue
			else:
				if packet.checkComp(("SYN", "ACK", "CONF"), exclusive=True) and:
					#checkdata
					recvConf = packet.data
					conf = md5.new(str(self.seq.num)+str(self.ack.num)).digest()
					if recvConf==conf:
						break

		if not resendsRemaining:
			raise RxPException(RxPException.CONNECTION_TIMEOUT)

		return packet


	def _sendSYNACK(self):

		# send SYN, ACK with sequence number
		comp = PacketAttributes.pickle(("SYN","ACK","CONF"))
		header = Header(
			srcPort=self.srcAddr[1],
			destPort=self.destAddr[1],
			seq=self.seq.num,
			ack=self.ack.num,
			recvWindow=self.recvWindow,
			comp=comp
			)
		# md5 hash of SYN,ACK
		verify = md5.new(str(self.seq.num)+str(self.ack.num)).digest()


		synack = Packet(header,verify)
		self.seq.next()

		resendsRemaining = self.resendLimit
		while resendsRemaining:

			# send SYNACK
			self.sendto(synack, self.destAddr)

			# wait to receive ACK. Only break out of loop
			# when ACK is received (or resendLimit exceeded)
			try:
				data, addr = self.recvfrom(self.recvWindow)
				packet = self._packet(data=data, addr=addr, checkSeq=False)
			except socket.timeout:
				logging.debug("_sendSYNACK() timeout")
				resendsRemaining -= 1
			except RxPException as e:
				if(e.type == RxPException.INVALID_CHECKSUM):
					continue
			else:
				
				if packet.checkAttrs(("SYN",), exclusive=True):
					# SYN was resent, resend SYNACK
					resendsRemaining = self.resendLimit
				elif packet.checkAttrs(("ACK",), exclusive=True):
					break


	def _sendACK(self):
		"""send ACK"""

		comp = PacketAttributes.pickle(("ACK","CONF"))
		header = Header(
			srcPort=self.srcAddr[1],
			destPort=self.destAddr[1],
			ack=self.ack.num,
			recvWindow=self.recvWindow,
			comp=comp
			)
		verify = md5.new(str(self.ack.num)).digest()
		packet = Packet(header,verify)
		self.sendto(packet, self.destAddr)

	def _recvACK(self):
		"""recv ACK"""
		waitsRemaining = self.resendLimit
		while waitsRemaining:

			# wait to receive ACK. Only break out of loop
			# when ACK is received (or waitsRemaining exceeded)
			try:
				data, addr = self.recvfrom(self.recvWindow)
				packet = self._packet(data=data, addr=addr, checkSeq=False)
			except socket.timeout:
				resendsRemaining -= 1
			except RxPException as e:
				if(e.type == RxPException.INVALID_CHECKSUM):
					continue
			else:
				if packet.checkAttrs(("ACK","CONF"), exclusive=True):
					conf = md5.new(str(self.ack.num)).digest()
					if conf = packet.data:
						return True
		return False
		



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
	_values = ["SYN", "CLOSE", "CONF","NM", "EOM",  
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
			
		comp
		compList = []
		pos = 0

		# add components to list if they match
		# an component offered in __values
		for item in PacketAttributes._values:
			if item in submittedComps:
				byte = 0b1 << pos
				comp
				compList.append(byte)
			pos += 1

		# generate binary from array
		if len(submittedComps) > 0:
			if len(comp
				compList) > 1:
				byteStr = reduce(lambda x,y: x | y, 
					comp
					compList)
			else:
				byteStr = comp
				compList[0]
		else:
			byteStr = 0
		
		return byteStr

	@staticmethod
	def unpickle(byteStr):
		"""creates an instance of PacketAttributes from
		a pickled instance (byte string)
		"""
		comp = list()
		pos = 0

		# check each bit in the byte string
		for item in PacketAttributes._values: 
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
		("recvWindow", uint16, 2),
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
			fieldName = item[0]
			fieldType = item[1]
			fieldVal = self.fields[fieldName]
			if fieldVal is not None:
				byteArr.extend(bytearray(
					fieldType(fieldVal)))

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
					str_ += repr(PacketAttributes.unpickle(
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

	def checkAttrs(self, expectedAttrs, exclusive=False):
		# verify expected attrs
		attrs = PacketAttributes.unpickle(
			self.header.fields["attrs"])

		if (exclusive and 
			len(attrs) != len(expectedAttrs)):
			return False
		else:
			for attr in expectedAttrs:
				if (attr is not None and 
					attr not in attrs):
					return False
		return True
			

	def __str__(self):
		d = self.__dict__ 
		d2 = {}
		for key in d.keys():
			d2[key] = str(d[key])
		return str(d2)











