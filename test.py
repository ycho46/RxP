from RxP import *
from RxPsub import *
import ctypes
import threading
import time
from functools import reduce

class Test:

	def __init__(self):
		self.tests = list()
		self.clientAddr = None
		self.serverAddr = None
		self.netAddr = None

	def add(self, func, *args):
		self.tests.append((func, args))

	def run(self, test=None, args=(), index=None):

		if test is not None:
			logging.info(test.__name__ + "...")
			success = test(*args)
			logging.info("...done")
			assert success
		elif index is not None:
			self.run(
				test=self.tests[index][0], 
				args=self.tests[index][1])
		else:
			self.runAll()

	def runAll(self):
		for test in self.tests:
			self.run(
				test=test[0], 
				args=test[1])

def testBind(port=8764):
	"""Tests socket.bind()"""

	assertions = []

	s1 = Zocket()
	s2 = Zocket()

	# test binding to a port that should be empty
	try:
		s1.bind(('127.0.0.1', port))
		assertions.append(True)
		print (assertions)
	except Exception:
		assertions.append(False)

	# test binding to a port that is in use
	try:
		s2.bind(('127.0.0.1', port))
		assertions.append(False)
	except Exception:
		assertions.append(True)

	return all(assertions)

def testPacketComponentsPickle(comp=None):
	"""tests PacketComponents class"""

	if comp is None:
		comp = ('SYN', 'ACK')

	compP = PacketComponents.pickle(comp)
	print (compP)
	comp2 = PacketComponents.unpickle(compP)
	print (comp2)
 	
	logging.debug(comp)
	logging.debug(comp2)

	assert len(comp) == len(comp2)

	assertions = []
	for index, item in enumerate(comp):
		assertions.append(item == comp2[index])

	return all(assertions)

def testHeaderPickle(fields=None):
	""""tests Header class"""

	if fields is None:
		comp = PacketComponents.pickle(('SYN', 'ACK'))
		fields = {
			"srcPort" : 8080,
			"destPort" : 8081,
			"seq" : 12345,
			"ack" : 12346,
			"recvWindow" : 4096,
			"length" : 4096,
			"checksum" : 123,
			"comp" : comp
			}

	h = Header(**fields)
	print (h)
	h2 = Header.unpickle(h.pickle())
	print (h2)

	logging.debug(h)
	logging.debug(h2) 

	assertions = []
	for item in Header.FIELDS:
		fieldName = item[0]
		val1 = h.fields[fieldName]
		val2 = h2.fields[fieldName]
		assertions.append(val1 == val2)

	return all(assertions)

def testPacketPickle(header=None, data="Hello World!"):
	"""tests the Packet class"""

	if header is None:
		comp = PacketComponents.pickle(('SYN', 'ACK'))
		header = Header(
			srcPort=8080,
			destPort=8081,
			seq=12345,
			recvWindow=4096,
			comp=comp
			)
	
	p1 = Packet(header, data)
	p2 = Packet.unpickle(p1.pickle(), toString=True)
	print (p1,'\n',p2)

	logging.debug(p1)
	logging.debug(p2)

	assertions = []

	for item in Header.FIELDS:
		name = item[0]
		f1 = p1.header.fields[name]
		f2 = p2.header.fields[name]
		assertions.append(f1 == f2)

	print (p1.data,p2.data)
	assertions.append(p1.data == p2.data)

	return all(assertions)

def testPacketChecksum(p=None):

	if p is None:
		comp = PacketComponents.pickle(("SYN",))
		print (comp)
		header = Header(
			srcPort=8080,
			destPort=8081,
			seq=123,
			rWindow=4096,
			comp=comp
			)

	p1 = Packet(header)
	print (p1)
	p2 = Packet.unpickle(p1.pickle())
	print (p1,'\n',p2)

	logging.debug("chksum1: " + str(p1.header.fields["checksum"]))
	logging.debug("chksum2: " + str(p2.header.fields["checksum"]))

	return p2.verify()

def testSocketConnect(clientAddr, serverAddr, netAddr, timeout=3):

	def runserver(server):
		try:
			server.listen()
			server.accept()
		except Exception as e:
			print ('exception runserver')
			logging.debug("server " + str(e))

	client = Zocket()
	client.bind(clientAddr)
	client.timeout = timeout

	server = Zocket()
	server.bind(serverAddr)
	server.timeout = timeout

	serverThread = threading.Thread(
		target=runserver, args=(server,))
	serverThread.setDaemon(True)
	serverThread.start()

	client.connect(netAddr)
	logging.debug("client")
	logging.debug("ack: " + str(client.ack.num))
	logging.debug("seq: " + str(client.seq.num))

	serverThread.join()
	logging.debug("server:")
	logging.debug("ack: " + str(server.ack.num))
	logging.debug("seq: " + str(server.seq.num))

	assertions = []

	assertions.append(client.connection == Connection.IDLE)
	assertions.append(server.connection == Connection.IDLE)
	assertions.append(client.ack.num == server.seq.num)
	assertions.append(client.seq.num == server.ack.num)

	print (assertions)

	return all(assertions)

def testSocketSendRcv(clientAddr, serverAddr, netAddr, timeout=3, message="Hello World!"):

	global servermsg
	servermsg = ""

	def runserver(server):
		global servermsg
		try:
			server.listen()
			server.accept()
			print("server.recv")
			servermsg = server.recv()
		except Exception as e:
			logging.debug("server " + str(e))

	# create client and server
	client = Zocket()
	client.bind(clientAddr)
	client.timeout = timeout
	client.acceptStrings = True

	server = Zocket()
	server.bind(serverAddr)
	server.timeout = timeout
	server.acceptStrings = True


	# run server
	serverThread = threading.Thread(
		target=runserver, args=(server,))
	serverThread.setDaemon(True)
	serverThread.start()

	# connect to server
	client.connect(netAddr)

	print ('message send!!!!!!')
	# send message
	client.send(message)
	print ('message sent@@@@@@')
	# close server
	serverThread.join()

	# check if server data matches 
	# message
	logging.debug("client msg: " + str(message))
	logging.debug("server msg: " + str(servermsg))

	print(message,'messg',servermsg,'servermsg')

	return message == servermsg

def testSocketTimeout(clientAddr, serverAddr, netAddr, timeout=1):
	
	assertions = []

	client = Zocket()
	client.timeout = timeout
	client.bind(clientAddr)
	server = Zocket()
	server.timeout = timeout
	server.bind(serverAddr)

	def runserver(server):
		server.listen()
		server.accept()

	def expectTimeout(func, *args):
		logging.debug(
			"trying " + func.__name__ + "...")
		try:
			func(*args)
		except myException as e:
			if e.type == myException.CONNECTION_TIMEOUT:
				assertions.append(True)
			else:
				assertions.append(False)

	# set up server
	serverThread = threading.Thread(
		target=runserver, args=(server,))
	serverThread.setDaemon(True)

	# test listening with a timeout
	expectTimeout(server.listen)

	# run server and connect
	serverThread.start()
	client.connect(netAddr)

	expectTimeout(client.recv)

	serverThread.join()

	return all(assertions)

def testRequestSendPermission(clientAddr, serverAddr, netAddr, timeout=3):

	message = "Hello World!"
	servermsg = " right back at ya"
	expectedResult = message + servermsg

	client = Zocket()
	client.timeout = timeout
	client.bind(clientAddr)
	client.acceptStrings = True
	server = Zocket()
	server.timeout = timeout
	server.bind(serverAddr)
	server.acceptStrings = True

	def runserver(server):
		server.listen()
		server.accept()
		msg = server.recv()
		server.send(msg + servermsg)
		msg2 = server.recv()

	# create and start server thread
	serverThread = threading.Thread(
		target=runserver, 
		args=(server,))
	serverThread.daemon = True
	serverThread.start()

	# connect to server
	client.connect(netAddr)

	client.send(message)
	result = client.recv()

	client.send(message)

	serverThread.join()

	logging.debug("expected: " + expectedResult)
	logging.debug("result: " + result)

	return result == expectedResult






