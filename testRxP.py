from RxP import *

client = Zocket()
client.bind(2300)

isconnected = client.connect(('127.0.0.1',2301))
while not isconnected:
	isconnected = client.connect(('127.0.0.1',2301))
#print 'send'


# message = client.receive(5)
# count = 0
# print message
# while message:
# 	message = client.receive(5)
# 	print message


# count = 500
# while count<1000:
# 	if client.send(str(count)):
# 		count = count + 1

message = client.receive(3)
print message
while message:
	message = client.receive(3)
	print message