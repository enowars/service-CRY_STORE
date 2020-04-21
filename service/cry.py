#!/usr/bin/env python3

import sys
import os
from binascii import unhexlify, hexlify
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
import sqlite3

import signal
signal.alarm(30)

conn = sqlite3.connect('flags.db')
cursor = conn.cursor()

def process_command(input_data : bytes):
	try:
		content, signature = input_data.split(b' ')
	except:
		print("Entered line must have format \"command[:param1[:param2]] signature\"")
		return

	split = content.split(b':')
	command = split[0].decode()
	data = split[1:]

	if command == 'receive':
		key = RSA.importKey(open('checker.pubkey','r').read())
		if not key.verify(content, (int(signature,16),)):
			print("invalid signature")
			return
		else:
			return receive(*data)
	if command == 'send_flag':
		return send_flag(data[0].decode())
	if command == 'send_flag_ids':
		return send_flag_ids(data[0].decode())

def receive(flag, round_number):
	global conn
	global cursor
	key1 = os.urandom(7)	
	key2 = os.urandom(7)	
	cipher1 = DES.new(b'\x00' + key1)
	cipher2 = DES.new(b'\x00' + key2)
	#encode the flag with triple-DES
	code = hexlify(cipher1.encrypt(cipher2.decrypt(cipher1.encrypt(flag)))).decode()
	key = hexlify(key1 + key2).decode()
	#store data in DB
	cursor.execute('insert into flags (tick, key, encoded) values (?,?,?);', [round_number, key, code])
	conn.commit()

def send_flag(flag_id):
	global conn
	global cursor
	cursor.execute('select key, encoded from flags where rowid = ' + flag_id + ';')
	des_key, encoded_flag = cursor.fetchone()
	key = RSA.importKey(open('server.pubkey','r').read())
	enc_des_key = pow(int(des_key,16), key.e, key.n)
	return ('%x:%s' % (enc_des_key, encoded_flag)).encode()
	
def send_flag_ids(tick):
	global conn
	global cursor
	cursor.execute('select rowid from flags where round = ' + tick + ';')
	flag_ids = cursor.fetchall()
	return b':'.join([tick.encode() for slag_id in flag_ids])

if __name__ == "__main__":
	while True:
		input_data = input("command:").strip().encode()
		if not input_data:
			sys.exit(0)
		res = process_command(input_data)
		print(res, file=sys.stderr)
		print(res)
