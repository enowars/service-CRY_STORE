#!/usr/bin/env python3

import sys
import os
from binascii import unhexlify, hexlify
import sqlite3
import string
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
			try:
				self.key = RSA.importKey(open('key.pem','r').read())
			except:
				self.key = RSA.generate(2048)
				key_file = open('key.pem','wb')
				key_file.write(self.key.export_key())
				key_file.close()
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
		while True:
			try:
				input_data = input("command: ").strip().encode()
				if not input_data:
					sys.exit(0)
				res = self.process_command(input_data)
				print(res, file=sys.stderr)
				print(res)
			except Exception as e:
				print(e, file=sys.stderr)

	def process_command(self, input_data : bytes) -> str:
		args = input_data.decode().split(' ') # split signature
		command = args[0]

		if command == 'receive':
			#checking signature
			if len(args) != 5:
				return "Entered line must have format \"receive category data tick signature\""
			signature = args[-1]
			args = args[1:-1]
			checker_key = RSA.importKey(open('checker.pubkey','r').read())
			if not verify(' '.join(args), signature, checker_key):
				return "invalid signature"
			return self.receive(*args)
		elif command == 'send':
			try:
				tick = int(args[1])
			except ValueError:
				print('First argument must be integer')
			return self.send(args[1])
		elif command == 'send_pubkey':
			return self.key.publickey().export_key().decode()
		else:
			return 'Unknown command'
			#print("Entered line must have format \"command [params]* [signature]\" separated by spaces")

	def receive(self, category : str, data : str, tick : str) -> str:
		if category == 'flag':
			data = decrypt(data, privkey = self.key)
		else:
			data = unhexlify(data).decode()
		#store data in DB
		try:
			tick = int(tick)
		except ValueError:
			return 'tick must be integer'
		if all([char in string.printable for char in data]):
			self.cursor.execute('insert into store (tick, category, data) values (?,?,?);', (tick, category, data))
			self.conn.commit()
			return sha256(data.encode()).hexdigest() + f":{self.cursor.lastrowid}"
		else:
			return f'Data not correctly decrypted: {data.encode()}'

	def send(self, flag_id : int) -> str:
		self.cursor.execute('select data,category from store where id = ' + str(flag_id) + ';')
		try:
			content, category = self.cursor.fetchone()
		except TypeError:
			return "Key not in Database"
		print(content, category, file=sys.stderr)
		if category == 'flag':
			key = RSA.importKey(open('checker.pubkey','r').read())
			return encrypt(content, key)
		else:
			return hexlify(content.encode()).decode()

if __name__ == "__main__":
	store = Store()
	store.run()
