#!/usr/bin/env python
# 
# usage: ./run-test.py [-d]
# note: NetEmu must be running at
# address 127.0.0.1, 5001 in its
# own process

from RxP import *
from test import *
import logging
import subprocess
import time
import os
import threading
import sys
import getopt

C_ADDR = ("127.0.0.1", 8080)
S_ADDR = ("127.0.0.1", 8081)
N_ADDR = ("127.0.0.1", 5000)

opts, args = getopt.getopt(sys.argv[1:], "d")

if opts and "-d" in opts[0]:
	logging.basicConfig(level=logging.DEBUG)
else:
	logging.basicConfig(level=logging.INFO)

# set up tests
tester = Test()
tester.add(testBind) # 0
tester.add(testPacketComponentsPickle) # 1
tester.add(testHeaderPickle) # 2
tester.add(testPacketPickle) # 3
tester.add(testPacketChecksum) # 4
tester.add(testSocketConnect, C_ADDR, S_ADDR, N_ADDR, 0.01) # 5
tester.add(testSocketSendRcv, C_ADDR, S_ADDR, N_ADDR, 0.01) # 6
tester.add(testSocketTimeout, C_ADDR, S_ADDR, N_ADDR, 0.01) # 7
tester.add(testRequestSendPermission, C_ADDR, S_ADDR, N_ADDR, 0.01) # 8

# run tests
# tester.run(index=0)
# tester.run(index=1)
# tester.run(index=2)
# tester.run(index=3)
# tester.run(index=4)
tester.run(index=5)
# tester.run(index=6)
# tester.run(index=7)
# tester.run(index=8)
