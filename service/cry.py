#!/usr/bin/env python3

import sys
import os
from binascii import unhexlify, hexlify
import sqlite3
from Crypto.PublicKey import RSA
from hashlib import sha256

import signal
from crypto import decrypt, encrypt, sign, verify

def timeout_handler():
  sys.exit(0)

#signal.signal(signal.SIGALRM, timeout_handler)
#signal.alarm(60)


class Store(object):

	def __init__(self):
		if os.path.isfile('key.pem'):
			self.key = RSA.importKey(open('key.pem','r').read())
		else:
			self.key = RSA.generate(2048)
			key_file = open('key.pem','wb')
			key_file.write(self.key.export_key())
			key_file.close()
		if os.path.isfile('checker.pubkey'):
			self.checker_key = RSA.importKey(open('checker.pubkey','r').read())
		else:
			raise Exception('Public Key of Checker not found')

		self.conn = sqlite3.connect('data/store.db')
		self.cursor = self.conn.cursor()
	
	def run(self):
		try:
			while True:
				input_data = input("command: ").strip().encode()
				if not input_data:
					sys.exit(0)
				res = self.process_command(input_data)
				print(res, file=sys.stderr)
				print(res)
		except Exception as e:
			print(e, file=sys.stdout)

	def process_command(self, input_data : bytes) -> str:
		args = input_data.decode().split(' ') # split signature
		command = args[0]

		if command == 'receive':
			#checking signature
			if len(args) != 5:
				return "Entered line must have format \"receive encoded_key encoded_flag tick signature\""
			signature = args[-1]
			checker_key = RSA.importKey(open('checker.pubkey','r').read())
			if not verify(' '.join(args[1:-1]), signature):
				return "invalid signature"
			else:
				receive(*args[1:-1])
		elif command == 'send':
			try:
				tick = int(args[2])
			except ValueError:
				return 'Second argument must be integer'
			return self.send(args[1], tick)
		elif command == 'send_pubkey':
			return self.key.publickey().export_key()
		else:
			return 'Unknown command'
			#print("Entered line must have format \"command [params]* [signature]\" separated by spaces")

	def receive(self, enc_key, enc_data, category, tick):
		data = decrypt(enc_data, enc_key)
		#store data in DB
		if all([char in string.printable for char in data]):
			self.cursor.execute('insert into store (tick, category, data) values (?,?,?);', (int(tick), category, data))
			self.conn.commit()
			return sha256(data.decode()).hexdigest()
		else:
			return 'Data not correctly decrypted'

	def send(self, category : str, tick : int) -> str:
		self.cursor.execute('select data from store where tick = ' + str(tick) + ' and category = \'' + category + '\';')
		content = self.cursor.fetchone()
		if category == 'flag':
			key = RSA.importKey(open('checker.pubkey','r').read())
			return encrypt(content, key)
		else:
			return content

if __name__ == "__main__":
	store = Store()
	store.run()
