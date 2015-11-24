
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


	def __init__(self):
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
		# number of times to resend a packet
		self.retries = 50
		# no timeout
		self.timeout = None
		# current connection status
		self.connection = Connection.NOT_ESTABLISHED
		# sending window size in bytes
		self.sWindow = 1
		# receiving window size in bytes
		self.rWindow = Packet.MAX_WINDOW_SIZE

		self.acceptStrings = False
		#random value for hash
		self.rand = 0


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
		# 1. sender sends SYN packet.
		# 2. receiver receives SYN then sends hashed SYN,ACK
		# 3. sender verifies it and sends hashed ACK and establishes
		# 4. host receives ACK and establishes connection
		1. sender sends syn
		2. server sends syn,ack with randomvalue
		3. sender sends ack with hash
		4. server verifies sends ack

		"""

		if self.srcAddr is None:
			raise myException("Socket not bound")


		# set destAddr
		self.destAddr = destAddr

		# set SYN
		self.seq.reset(0)

		# send SYN and and verify SYN,ACK upon receiving 
		synAck = self._sendSYN(firstSYN=True)

		# set ACK
		ack = synAck.header.fields["seq"]
		self.ack.reset(ack + 1)

		# send hashed ACK
		self._sendACK(firstSYN=True)

		# if sender receives ack from server after verifying hash
		# establish connection
		if self._recvACK():
			# connection established
			self.connection = Connection.IDLE

			# set to be sender
			self.isSender = True

	def listen(self):
		"""listens on the given port number for 
		packets. Blocks until a SYN packet is received.
		"""

		if self.srcAddr is None:
			raise myException("Socket not yet bound")

		waitTime = self.retries*100
		while waitTime:
			#print ('listening')
			# wait to receive SYN
			try:
				#print ('listen receving')
				data, addr = self.recvfrom(self.rWindow)

				#print ("recv data listen", Packet.unpickle(data), addr)
				packet = self._packet(data, checkSeq=False)

				#print ('packet: listen')
				
			except socket.timeout:
				waitTime -= 1
				continue
			except myException as e:
				#print ('exception thrown')
				if(e.type == myException.INVALID_CHECKSUM):
					continue
			else:
				#print ('about the check SYN')
				if packet.checkComp(("SYN",), exclusive=True):
					#print ('received SYN')
					break
				else:
					waitTime -= 1

		if not waitTime:
			raise myException(myException.CONNECTION_TIMEOUT)

		# set ACM 
		ack = packet.header.fields["seq"]
		self.ack.reset(ack+1)

		# set dest addr
		self.destAddr = addr

		# accept() should be called directly after
		# listen() in order to complete the handshake
	def accept(self):
		"""
		The receiver side of 4-way handshake
		"""

		#set seq number
		self.seq.reset(0)

		#print ('about to send synACk')
		# sends hashed SYNACK and receive hashed ACK
		packet = self._sendSYNACK(firstSYN=True)
		#print ('sent synack and received Ack')

		self._sendACK()
		self.connection = Connection.IDLE
		self.isSender = False


		# verified ACK + hash from _sendSYNACK and established
		# send ACK
		#sendACK
		# checks ACK
		# if self._recvACK(firstSYN=True):
		# 	# update connection status
		# 	self.connection = Connection.IDLE

		# 	# set to receiver
		# 	self.isSender = False
		# else:
		# 	raise myException("Wrong ACK")

	def _sendSYN(self,firstSYN=False):

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
			self.sendto(packet,self.destAddr)
			#print ('sending SYN')

			try:
				#print ("sendSYN is receiving")
				data, addr = self.recvfrom(self.rWindow)

				#print ("recv data", Packet.unpickle(data), addr)
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
					#print (p1,'SYN ACK',self.rand)
					# self.randValue = packet.
				if packet.checkComp(("SYN", "ACK"), exclusive=True):
					break

		if not numRetries:
			raise myException(myException.CONNECTION_TIMEOUT)

		return packet


	def _sendSYNACK(self,firstSYN=False):

		# send SYN, ACK with sequence number
		comp = PacketComponents.pickle(("SYN","ACK"))
		header = Header(
			srcPort=self.srcAddr[1],
			destPort=self.destAddr[1],
			seq=self.seq.num,
			ack=self.ack.num,
			rWindow=self.rWindow,
			comp=comp
			)
		
		#print ('sendSYNACK',firstSYN)
		# sends random value for first SYN recieved to verify for 4-way handshake
		if firstSYN:
			#print ('first synning')
			self.rand = randint(1,99)
			#print (header,'header and randvalue', self.rand)
			synack = Packet(header,str(self.rand))
			#print (synack)
		else:
			synack = Packet(header)
		self.seq.next()

		numRetries = self.retries
		while numRetries:

			# send SYNACK
			self.sendto(synack, self.destAddr)

			# wait to receive ACK. Only break out of loop
			# when ACK is received (or retries exceeded)
			try:
				data, addr = self.recvfrom(self.rWindow)
				packet = self._packet(data=data, addr=addr, checkSeq=False)
			except socket.timeout:
				logging.debug("_sendSYNACK() timeout")
				numRetries -= 1
			except myException as e:
				if(e.type == myException.INVALID_CHECKSUM):
					continue
			else:
				
				if packet.checkComp(("SYN",), exclusive=True):
					# SYN was resent, resend SYNACK
					numRetries = self.retries
				elif packet.checkComp(("ACK",), exclusive=True):
					#print ("ack recved",packet.data)
					#print ('test1')
					verify = str(self.rand)
					#print (verify, 'verify num')
					verify2 = hashlib.md5(verify.encode('utf-8')).hexdigest()
					#print (verify2,'verify')
					verify2 = verify2[:2]
					#print (verify2, packet.data)
					if isinstance(packet.data, str):
						if verify2 == packet.data:
							#print ('breaking')
							break
						else:
							raise myException("Wrong hash ACK")
					elif isinstance(packet.data, unicode):
						if verify2 == packet.data.decode('utf-8'):
							#print ('breaking')
							break
						else:
							raise myException("Wrong hash ACK")



	def _sendACK(self,firstSYN=False):
		"""send ACK"""
		#print ('sendACK ')
		comp = PacketComponents.pickle(("ACK",))
		header = Header(
			srcPort=self.srcAddr[1],
			destPort=self.destAddr[1],
			ack=self.ack.num,
			rWindow=self.rWindow,
			comp=comp
			)
		if firstSYN:
			verify = self.rand
			verify = hashlib.md5(verify.encode('utf-8')).hexdigest()
			#print ('verify',verify)
			packet = Packet(header,verify)
			#print ('ACK packet', packet)
		else:
			packet = Packet(header)
		self.sendto(packet, self.destAddr)

	def _recvACK(self):
		"""recv ACK"""
		waitsRemaining = self.retries
		while waitsRemaining:

			# wait to receive ACK. Only break out of loop
			# when ACK is received (or waitsRemaining exceeded)
			try:
				data, addr = self.recvfrom(self.rWindow)
				packet = self._packet(data=data, addr=addr, checkSeq=False)
			except socket.timeout:
				numRetries -= 1
			except myException as e:
				if(e.type == myException.INVALID_CHECKSUM):
					continue
			else:
				if packet.checkComp(("ACK",), exclusive=True):
					#print('recved ACK return T')
					return True
		return False
		

	def sendto(self, packet, addr):
		name = "sender" if self.isSender else "receiver"
		logging.debug(name + ": sendto: " + str(packet))
		logging.debug("")
		self._socket.sendto(packet.pickle(), addr)

	def recvfrom(self, rWindow, expectedAttrs=None):
		while True:
			#print ("recv loop")
			try:
				data, addr = self._socket.recvfrom(self.rWindow)
				break
			except socket.error as e:
				if e.errno == 35:
					continue
				else:
					raise e

		name = "sender" if self.isSender else "receiver"
		logging.debug(name + ": recvfrom: " + str(Packet.unpickle(data)))
		logging.debug("")
		return (data, addr)

	def _packet(self, data, addr=None, checkSeq=True, checkAck=False):
		""" reconstructs a packet from data and verifies
		checksum and address (if addr is not None).
		"""
		#print ("_packet 0")
		#print (data)
		packet = Packet.unpickle(data, toString=self.acceptStrings)
		#print (packet)
		
		# verify checksum
		if not packet.verify():
			raise myException(myException.INVALID_CHECKSUM)

		#print ("_packet 1")
		# verify seqnum
		if checkSeq:
			
			#print ("_packet 2")
			comp = PacketComponents.unpickle(
				packet.header.fields["comp"])
			isSYN = packet.checkComp(("SYN",), exclusive=True)
			isACK = packet.checkComp(("ACK",), exclusive=True)
			
			packetSeqNum = packet.header.fields["seq"]
			socketAckNum = self.ack.num
			
			if (not isSYN and packetSeqNum and 
				socketAckNum != packetSeqNum):
				raise myException(
					myException.SEQ_MISMATCH)
			elif not isACK:
				self.ack.next()


		# if checkAck is sent, it should be set to the
		# expected ack num
		if checkAck:

			#print ("_packet 3")
			comp = PacketComponents.unpickle(
				packet.header.fields["comp"])
			
			packetAckNum = packet.header.fields["ack"]

			ackMismatch = (int(packetAckNum) - checkAck - 1)

			if packetAckNum and ackMismatch:
				logging.debug("acknum: " + str(packetAckNum))
				return ackMismatch

		return packet

	# def send(self, msg):
	# 	"""sends a message"""

	# 	if self.srcAddr is None:
	# 		raise myException("Socket not yet bound")
		
	# 	# list for data fragments
	# 	dataList = list()
	# 	# list for packets waiting to be sent
	# 	packetList = list()
	# 	# list for packets that have been sent but have not been ACKed
	# 	sentList = list()

	# 	lastSeqNum = self.seq.num

	# 	# break up message into chunks (dataList)
	# 	for i in range(0, len(msg), Packet.DATA_LENGTH):
	# 		# extract data from msg
	# 		if i+Packet.DATA_LENGTH > len(msg):
	# 			dataList.append(msg[i:])
	# 		else:	
	# 			dataList.append(msg[i:i+Packet.DATA_LENGTH])

	# 	# construct list of packets (packetList)
	# 	for data in dataList:
			
	# 		first = data == dataList[0]
	# 		last = data == dataList[-1]
	
	# 		# set beginning and end of message
	# 		piece = list()
	# 		if first:
	# 			piece.append("B")
	# 		if last:
	# 			piece.append("E")

	# 		# create packets
	# 		comp = PacketComponents.pickle(piece)
	# 		header = Header(
	# 			srcPort=self.srcAddr[1],
	# 			destPort=self.destAddr[1],
	# 			seq=self.seq.num,
	# 			comp=comp
	# 			)
	# 		packet = Packet(header, data)
	# 		self.seq.next()

	# 		# print ('packet', packet)

	# 		# add packet to head of list
	# 		packetList.append(packet)

	# 	numRetries = self.retries
	# 	while packetList and numRetries:
	# 		# send packets (without waiting for ack)
	# 		# until sWindow is 0 or all packets
	# 		# have been sent
	# 		sWindow = self.sWindow
	# 		while sWindow and packetList:
	# 			# get packet from the list
	# 			packet = packetList.pop(0)
	# 			# print (packet)
	# 			# print (packetList)
	# 			# send packet
	# 			self.sendto(packet, self.destAddr)
	# 			lastSeqNum = packet.header.fields["seq"]

	# 			# decrement send window, add to sentList
	# 			sWindow -= 1
	# 			sentList.append(packet)



















	# 		# wait for ack
	# 		try:
	# 			# wait for ACK or SYNACK (resent)
	# 			data, addr = self.recvfrom(self.rWindow)
	# 			packet = self._packet(data, checkSeq=False, checkAck=lastSeqNum)

	# 		except socket.timeout:

	# 			# reset send window and resend last packet
	# 			sWindow = 1
	# 			numRetries -= 1
	# 			# logging.debug("send() timeout")
	# 			# logging.debug("resends: "  + str(numRetries))
				
	# 			# prepend packetList with sentList, then
	# 			# clear sentList
	# 			sentList.reverse()
	# 			packetList = sentList+packetList
	# 			sentList.clear()

	# 		except myException as e:
	# 			if(e.type == myException.INVALID_CHECKSUM):
	# 				continue

	# 		else:
	# 			sWindow += 1
	# 			# test is ack mismatch occured
	# 			if isinstance(packet, int):
	# 				# logging.debug("ACK MISMATCH:")
	# 				# logging.debug("seqnum: " + str(lastSeqNum))
	# 				# logging.debug(packet)
	# 				# logging.debug(sentList)

	# 				while packet < 0:
	# 					popped = [sentList.pop()]
	# 					packetList = popped + packetList
	# 					packet += 1	

	# 			elif packet.checkComp(("SYN","ACK"), exclusive=True):
	# 				# resend ACK acknowledging SYNACK
	# 				self._sendACK()

	# 				numRetries = self.retries

	# 				# prepend packetList with sentList, then
	# 				# clear sentList
	# 				sentList.reverse()
	# 				packetList = sentList+packetList
	# 				sentList.clear()


	# 			elif packet.checkComp(("ACK",), exclusive=True):
	# 				# increase sWindow back to original
	# 				# size (no positive flow control), 
	# 				# remove packet from sentList
	# 				self.seq.reset(packet.header.fields["ack"])

	# 				numRetries = self.retries
	# 				# pop off packet that was just acked
	# 				# (except for final ack)
	# 				if sentList:
	# 					sentList.pop(0)


	# def recv(self):
	# 	"""receives a message"""
	# 	print ('receving')
		
	# 	if self.srcAddr is None:
	# 		print ('src recv exceptions')
	# 		raise myException("Socket not bound")


	# 	if self.connetion != Connection.IDLE:
	# 		print ('connection recv exceptions')
	# 		raise myException("Connection status not idle")

	# 	print ('passed recv exceptions')
		
	# 	# decode and receive message
	# 	if(self.acceptStrings):
	# 		message = ""
	# 	else:
	# 		message = bytes()

	# 	waitTime = self.numRetries
	# 	while waitTime:
	# 		print ('recv loop')
	# 		# get packet
	# 		try:
	# 			# listen for data
	# 			data, addr = self.recvfrom(self.rWindow)
	# 			print ('data recv', data)
	# 		except socket.timeout:
	# 			# if no data is sent, wait again
	# 			waitTime -= 1
	# 			continue
			
	# 		# deserialize data into packet
	# 		try:
	# 			# logging.debug("acknum: " + str(self.ack.num))
	# 			packet = self._packet(data, checkSeq=False)
	# 		except myException as e:
	# 			# logging.debug(str(e))
	# 			if e.type == myException.INVALID_CHECKSUM:
	# 				continue
	# 			if e.type != myException.SEQ_MISMATCH:
	# 				raise e
	# 		else:
	# 			# multiplex on packet attributes
	# 			# if packet.checkComp(("SRQ",)):

	# 			# 	# request permission to send data
	# 			# 	# and break out of loop
	# 			# 	self._grantSendPermission()
				
	# 			# # NM, E, or middle of message
	# 			# else:

	# 			if packet.header.fields["seq"] < self.ack.num:
	# 				# an ack was dropped and this packet
	# 				# was resent. ignore data, but send ack
	# 				self._sendACK()
	# 			else:
	# 				self.ack.next()
	# 				message += packet.data
	# 				# send ACK
	# 				self._sendACK()

	# 			# stop looping if E
	# 			if packet.checkComp(("E",)):
	# 				break

	# 			if packet.checkComp(("CLOSE", )):
	# 				self._sendACK()
	# 				self._socket.close()
	# 				break

	# 	# if not waitTime:
	# 	# 	raise myException(
	# 	# 		myException.CONNECTION_TIMEOUT)
	# 	return message

	def close(self):
		# create packets
		comp = PacketComponents.pickle(("CLOSE",))
		header = Header(
			srcPort=self.srcAddr[1],
			destPort=self.destAddr[1],
			seq=self.seq.num,
			comp=comp
			)
		packet = Packet(header)
		self.seq.next()

		waitTime = self.retries
		while waitTime:
			
			self.sendto(packet, self.destAddr)

			try:
				data, addr = self.recvfrom(self.rWindow)
				packet = self._packet(data, checkSeq=False)

			except socket.timeout:
				waitTime -= 1
				continue

			except myException as e:
				if(e.type == myException.INVALID_CHECKSUM):
					continue
			else:
				if packet.checkComp(("ACK",), exclusive=True):
					self._socket.close()
					break
				else:
					waitTime -= 1
# ""
	
	def send(self, msg):
		"""sends a message"""

		if self.srcAddr is None:
			raise myException("Socket not bound")
		
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
				self.sendto(packet, self.destAddr)
				lastSeqNum = packet.header.fields["seq"]

				# decrement send window, add 
				# to sentQ
				sWindow -= 1
				sentQ.append(packet)
				print ('message packet sent')
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
			print("1")
			raise myException("Socket not bound")

		print("3")
		if self.connection != Connection.IDLE:
			print("2")
			raise myException("Connection status not idle")
		

		print("4")
		# decode and receive message
		if(self.acceptStrings):
			message = ""
		else:
			message = bytes()

		waitLimit = self.retries
		while waitLimit:
			# get packet
			print ('waiting')
			try:
				# listen for data
				data, addr = self.recvfrom(self.rWindow)
				print ('recv data',data)
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












