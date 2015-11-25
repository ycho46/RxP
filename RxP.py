import sys
import socket
import struct
import binascii
import ctypes
import math
import logging
from collections import OrderedDict
from collections import deque
from sys import getsizeof
from random import *
from functools import reduce
import hashlib
from RxPsub import *

class Zocket:
	"""Zocket is the main protocol that hold all API methods for bind(), connect(), send(), recieve(), and close()."""

	# constructor for Zocket
	def __init__(self):

		if sys.hexversion != 50594800:
			raise myException("Please run with Python version 3.4.3")

		# UDP socket
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		# destAddr (ip, port)
		self.destAddr = None
		# srcAddr (port)
		self.srcAddr = None
		# sequence number
		self.seq = counter(max=Packet.MAX_SEQ_NUM)
		# ack number
		self.ack = counter(max=Packet.MAX_SEQ_NUM)
		# sender or receiver
		self.isSender = False
		# number of times to retry sending a packet
		self.retries = 50
		# current connection stats
		self.connection = Connection.NOT_ESTABLISHED
		# sending window size in bytes
		self.sWindow = 1
		# receiving window size in bytes
		self.rWindow = Packet.MAX_WINDOW_SIZE
		# boolean value for setting msgs to be bytes or strs
		self.strMsg = False
		#random value for hash
		self.rand = 0
		# no timeout
		self.timeout = None


	# timeout is used to interact with
	# self._socket's timeout property
	@property
	def timeout(self):
   		return self._socket.gettimeout()
	@timeout.setter
	def timeout(self, value):
		self._socket.settimeout(value)
	

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
# 	""
	def connect(self, destAddr):
		"""
		initiates connection with in input destAddr(ip,port)
		Connects using 4-way handshake.
		1. Sender sends SYN packet
		2. Receiver receives SYN and sends SYN,ACK with
			 randomvalue for authentication
		3. Sender receives SYN,ACK with randomvalue and 
			sends ACK packet with hashed randomvalue
		4. Receiver verifies authenticity and establishes 
			connection upon verification and sends ACK
		5. Sender receives ACK and establishes connection 
		"""

		if self.srcAddr is None:
			raise myException("Socket is not bound")

		# set destAddr
		self.destAddr = destAddr

		# set SYN
		self.seq.reset(0)

		# send SYN and and verify SYN,ACK upon receiving 
		synAck = self._sendSYN(firstSYN=True)

		# set ACK
		ack = synAck.header.fields["seq"]
		self.ack.reset(ack + 1)

		# send ACK with randomvalue
		self._sendACK(firstSYN=True)

		# if sender receives ack from server after verifying hash
		# establish connection
		if self._recvACK():
			# connection established
			self.connection = Connection.IDLE

			# set to be sender
			self.isSender = True

	def listen(self):
		"""listens on port number for SYN packets.
		"""

		if self.srcAddr is None:
			raise myException("Socket not yet bound")

		numWait = self.retries*100
		while numWait:
			# loop until SYN is received
			try:
				data, addr = self.recvfrom(self.rWindow)
				packet = self._packet(data, checkSeq=False)
				
			except socket.timeout:
				numWait -= 1
				continue
			except myException as e:
				if(e.type == myException.INVALID_CHECKSUM):
					continue
			else:
				if packet.checkComp(("SYN",), exclusive=True):
					break
				else:
					numWait -= 1

		if not numWait:
			raise myException(myException.CONNECTION_TIMEOUT)

		# set ACK
		ack = packet.header.fields["seq"]
		self.ack.reset(ack+1)

		# set destAddr
		self.destAddr = addr

	def accept(self):
		"""
		The receiver side of 4-way handshake.
		This method should be called right after listen()
		"""

		#set seq number
		self.seq.reset(0)

		# sends SYNACK with random value and
		# receives ACK with hashed random value
		packet = self._sendSYNACK(firstSYN=True)

		# ACK with hahsed random value has been verfied
		# so send an ACK and server establishes connection 
		self._sendACK()
		self.connection = Connection.IDLE
		self.isSender = False

	def _sendSYN(self,firstSYN=False):
		"""
		method for sending SYN
		when firstSYN is True, initiates a handshake by sending SYN.
		"""

		#create SYN packet
		comp = PacketComponents.pickle(("SYN",))
		header = Header(srcPort=self.srcAddr[1],
			destPort=self.destAddr[1],seq=self.seq.num,
			rWindow=self.rWindow, comp=comp)
		packet = Packet(header)
		self.seq.next()

		#set number of retries to try sending and receiving SYN,ACK
		numRetries = self.retries
		while numRetries:
			# send SYN
			# self.sendto(packet,self.destAddr)

			self._socket.sendto(packet.pickle(), self.destAddr)
			#loops till SYN,ACK is received or timeout
			try:
				data, addr = self.recvfrom(self.rWindow)
				packet = self._packet(data=data, addr=addr, checkSeq=False)
			except socket.timeout:
				numRetries -=1
			except myException as e:
				if(e.type == myException.INVALID_CHECKSUM):
					continue
			else:

				if packet.checkComp(("SYN", "ACK"), exclusive=True) and firstSYN:
					p1 = Packet.unpickle(packet.pickle(), toString=True)
					self.rand = p1.data
					print (p1,'SYN ACK',self.rand)
					break

		if not numRetries:
			raise myException(myException.CONNECTION_TIMEOUT)

		return packet


	def _sendSYNACK(self,firstSYN=False):
		"""
		used by server to send SYN,ACK and the random value
		"""
		# create packet with SYN, ACK
		comp = PacketComponents.pickle(("SYN","ACK"))
		header = Header(
			srcPort=self.srcAddr[1],
			destPort=self.destAddr[1],
			seq=self.seq.num,
			ack=self.ack.num,
			rWindow=self.rWindow,
			comp=comp
			)
		
		# sends packet with random value for 4-way handshake
		if firstSYN:
			self.rand = randint(1,99)
			synack = Packet(header,str(self.rand))
		else:
			synack = Packet(header)
		self.seq.next()

		#set number of retries to send the packet
		numRetries = self.retries
		while numRetries:
			# send packet
			# self.sendto(synack, self.destAddr)

			self._socket.sendto(synack.pickle(), self.destAddr)
			# loop until ACK with correct hash value is received
			try:
				data, addr = self.recvfrom(self.rWindow)
				packet = self._packet(data=data, addr=addr, checkSeq=False)
			except socket.timeout:
				numRetries -= 1
			except myException as e:
				if(e.type == myException.INVALID_CHECKSUM):
					continue
			else:
				# When received packet is a SYN, resend packet
				if packet.checkComp(("SYN",), exclusive=True):
					numRetries = self.retries
				# When ACK is received, verfiity authenticity
				elif packet.checkComp(("ACK",), exclusive=True):
					verify = str(self.rand)
					verify2 = hashlib.md5(verify.encode('utf-8')).hexdigest()
					verify2 = verify2[:2]
					print (verify2, packet.data)
					if isinstance(packet.data, str):
						if verify2 == packet.data:
							break
						else:
							raise myException("Wrong hash ACK")
					else:
						if verify2 == packet.data.decode('utf-8'):
							break
						else:
							raise myException("Wrong hash ACK")


	def _sendACK(self,firstSYN=False):
		"""
		send ACK used for sending ACK with has and regular ACK
		"""
		comp = PacketComponents.pickle(("ACK",))
		header = Header(
			srcPort=self.srcAddr[1],
			destPort=self.destAddr[1],
			ack=self.ack.num,
			rWindow=self.rWindow,
			comp=comp
			)
		# when it is the first ACK after SYN,ACK
		if firstSYN:
			verify = self.rand
			verify = hashlib.md5(verify.encode('utf-8')).hexdigest()
			packet = Packet(header,verify)
		else:
			packet = Packet(header)
		self._socket.sendto(packet.pickle(), self.destAddr)

	def _recvACK(self):
		"""
		recvACK used sender
		"""
		# set number of retries to recive ACK before timeout
		numRetries = self.retries
		while numRetries:
			# loop until ACK value is received
			try:
				data, addr = self.recvfrom(self.rWindow)
				packet = self._packet(data=data, addr=addr, checkSeq=False)
			except socket.timeout:
				numRetries -= 1
			except myException as e:
				if(e.type == myException.INVALID_CHECKSUM):
					continue
			else:
				#When ACK received return True
				if packet.checkComp(("ACK",), exclusive=True):
					return True
		return False
		

	# def sendto(self, packet, addr):
	# 	"""
	# 	send packet addr
	# 	"""
	# 	name = "sender" if self.isSender else "receiver"
	# 	logging.debug(name + ": sendto: " + str(packet))
	# 	logging.debug("")
	# 	self._socket.sendto(packet.pickle(), addr)

	def recvfrom(self, rWindow, expectedAttrs=None):
		while True:
			try:
				data, addr = self._socket.recvfrom(self.rWindow)
				break
			except socket.error as e:
				if e.errno == 35:
					continue
				else:
					raise e
		return (data, addr)

	def _packet(self, data, addr=None, checkSeq=True, checkAck=False):
		""" 
		assembles packet from data verify checksum and addr
		"""
		packet = Packet.unpickle(data, toString=self.strMsg)
		# verify the checksum
		if not packet.verify():
			raise myException(myException.INVALID_CHECKSUM)
		# verify sequence num
		if checkSeq:
			comp = PacketComponents.unpickle(
				packet.header.fields["comp"])
			isSYN = packet.checkComp(("SYN",), exclusive=True)
			isACK = packet.checkComp(("ACK",), exclusive=True)
			packetSeqNum = packet.header.fields["seq"]
			socketAckNum = self.ack.num
			
			if (not isSYN and packetSeqNum and socketAckNum != packetSeqNum):
				raise myException(myException.SEQ_MISMATCH)
			elif not isACK:
				self.ack.next()


		# if checkAck is sent, set ack to expected ACK
		if checkAck:
			comp = PacketComponents.unpickle(
				packet.header.fields["comp"])
			packetAckNum = packet.header.fields["ack"]
			ackMismatch = (int(packetAckNum) - checkAck - 1)
			if packetAckNum and ackMismatch:
				logging.debug("acknum: " + str(packetAckNum))
				return ackMismatch

		return packet


	def close(self):
		# assemble packets
		comp = PacketComponents.pickle(("CLOSE",))
		header = Header(
			srcPort=self.srcAddr[1], destPort=self.destAddr[1],
			seq=self.seq.num, comp=comp
			)
		packet = Packet(header)
		self.seq.next()
		#set number of waits before close
		numWait = self.retries
		while numWait:
			#send close packet
			self._socket.sendto(packet.pickle(), self.destAddr)
			#loop until ACK is received
			try:
				data, addr = self.recvfrom(self.rWindow)
				packet = self._packet(data, checkSeq=False)
			except socket.timeout:
				numWait -= 1
				continue
			except myException as e:
				if(e.type == myException.INVALID_CHECKSUM):
					continue
			else:
				if packet.checkComp(("ACK",), exclusive=True):
					self._socket.close()
					break
				else:
					numWait -= 1
	
	def send(self, msg):
		"""
		method for sending message
		"""
		if self.srcAddr is None:
			raise myException("Socket is bound to port")
		
		# FIFO queues for data fragments, queue for packets
		# waiting to be sent, and queue for packets that
		# have been sent but have not been ACKed
		dataQ = deque()
		packetQ = deque()
		sentQ = deque()
		lastSeqNum = self.seq.num

		# break up message into chunks (dataQ)
		for i in range(0, len(msg), Packet.DATA_LENGTH):
			# extract data from msg
			if i+Packet.DATA_LENGTH > len(msg):
				dataQ.append(msg[i:])
			else:	
				dataQ.append(
					msg[i:i+Packet.DATA_LENGTH])

		# construct list of packets (packetQ)
		for data in dataQ:
			
			first = data == dataQ[0]
			last = data == dataQ[-1]
	
			# set attributes
			attrL = list()
			if first:
				attrL.append("B")
			if last:
				attrL.append("E")

			# create packets
			comp = PacketComponents.pickle(attrL)
			header = Header(
				srcPort=self.srcAddr[1],
				destPort=self.destAddr[1],
				seq=self.seq.num,
				comp=comp
				)
			packet = Packet(header, data)
			self.seq.next()

			# add packet to head of queue
			packetQ.append(packet)

		resendsRemaining = self.retries
		while packetQ and resendsRemaining:
			# send packets (without waiting for ack)
			# until sWindow is 0 or all packets
			# have been sent
			sWindow = self.sWindow
			while sWindow and packetQ:
				# grab a packet from end the list
				packet = packetQ.popleft()

				# send packet
				self._socket.sendto(packet.pickle(), self.destAddr)
				lastSeqNum = packet.header.fields["seq"]

				# decrement send window, add 
				# to sentQ
				sWindow -= 1
				sentQ.append(packet)
				#print ('message packet sent')
			# wait for ack
			try:
				# wait for ACK or SYNACK (resent)
				data, addr = self.recvfrom(self.rWindow)
				packet = self._packet(data, checkSeq=False, checkAck=lastSeqNum)

			except socket.timeout:

				# reset send window and resend last packet
				sWindow = 1
				resendsRemaining -= 1
				logging.debug("send() timeout")
				logging.debug("resends: "  + str(resendsRemaining))
				
				# prepend packetQ with sentQ, then
				# clear sentQ
				sentQ.reverse()
				packetQ.extendleft(sentQ)
				sentQ.clear()

			except myException as e:
				if(e.type == myException.INVALID_CHECKSUM):
					continue

			else:
				sWindow += 1
				# test is ack mismatch occured
				if isinstance(packet, int):
					logging.debug("ACK MISMATCH:")
					logging.debug("seqnum: " + str(lastSeqNum))
					logging.debug(packet)
					logging.debug(sentQ)

					while packet < 0:
						packetQ.appendleft(sentQ.pop())
						packet += 1	

				elif packet.checkComp(("SYN","ACK"), exclusive=True):
					# resend ACK acknowledging SYNACK
					self._sendACK()

					resendsRemaining = self.retries

					# prepend packetQ with sentQ, then
					# clear sentQ
					sentQ.reverse()
					packetQ.extendleft(sentQ)
					sentQ.clear()

				elif packet.checkComp(("ACK",), exclusive=True):
					# increase sWindow back to original
					# size (no positive flow control), 
					# remove packet from sentQ
					self.seq.reset(packet.header.fields["ack"])

					resendsRemaining = self.retries
					# pop off packet that was just acked
					# (except for final ack)
					if sentQ:
						sentQ.popleft()


	def recv(self):
		"""receives a message"""
		
		if self.srcAddr is None:
			raise myException("Socket not bound")

		if self.connection != Connection.IDLE:
			raise myException("Connection status not idle")
		
		# decode and receive message
		if(self.strMsg):
			message = ""
		else:
			message = bytes()

		waitLimit = self.retries
		while waitLimit:
			# get packet
			#print ('waiting')
			try:
				# listen for data
				data, addr = self.recvfrom(self.rWindow)
				#print ('recv data',data)
			except socket.timeout:
				# if no data is sent, wait again
				waitLimit -= 1
				continue
			
			# deserialize data into packet
			try:
				logging.debug("acknum: " + str(self.ack.num))
				packet = self._packet(data, checkSeq=False)
			except myException as e:
				logging.debug(str(e))
				if e.type == myException.INVALID_CHECKSUM:
					continue
				if e.type != myException.SEQ_MISMATCH:
					raise e
			else:
				# multiplex on packet attributes
				# if packet.checkComp(("SRQ",)):

				# 	# request permission to send data
				# 	# and break out of loop
				# 	self._grantSendPermission()
				
				# # NM, E, or middle of message
				# else:

				if packet.header.fields["seq"] < self.ack.num:
					# an ack was dropped and this packet
					# was resent. ignore data, but send ack
					self._sendACK();
				else:
					self.ack.next()
					message += packet.data
					# send ACK
					self._sendACK()

				# stop looping if E
				if packet.checkComp(("E",)):
					break

				if packet.checkComp(("CLOSE", )):
					self._sendACK()
					self._socket.close()
					break

		# if not waitLimit:
		# 	raise myException(
		# 		myException.CONNECTION_TIMEOUT)
		return message












