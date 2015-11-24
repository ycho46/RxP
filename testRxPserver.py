from RxP import *

server = Zocket()
server.bind(2301)

server.listen()

connectionSocket = server.accept()




# count = 0
# while count<1500:
# 	if connectionSocket.send(str(count)):
# 		count = count + 1
# 		print count

# message = connectionSocket.receive(5)
# count = 0
# print message
# while message:
# 	message = connectionSocket.receive(5)
# 	print message

print ('sending')
connectionSocket.send('hello')
connectionSocket.send('hello')