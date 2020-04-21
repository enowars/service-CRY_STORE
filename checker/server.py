#!/usr/bin/env python3

from binascii import unhexlify, hexlify
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import client
import os
import sqlite3

key = RSA.importKey(open('server.privkey','r').read())
counter = 0

conn = sqlite3.connect('server_flags.db')
cursor = conn.cursor()

def send_flag():
	global key
	global counter
	global conn
	global cursor
	"""matches "receive" from client"""
	flag = b'flag{' + hexlify(os.urandom(13)) + b'}'
	content = b'receive:' + flag + (b':%d' % counter)
	counter += 1
	cursor.execute('insert into flags (tick, flag) values (?,?);', (counter, flag.decode()))
	conn.commit()
	signature = hex(key.sign(content, 1)[0])[2:].encode()
	input_data = content + b' ' + signature
	client.process_command(input_data)

def check_flag(flag_id : int):
	global key
	"""matches "send_flag" from client"""
	input_data = b'send_flag:%d 00' % flag_id
	res = client.process_command(input_data)
	enc_des_key, enc_flag = res.split(b':')
	des_key = long_to_bytes(pow(int(enc_des_key,16), key.d, key.n))

	cipher1 = DES.new(b'\x00' + des_key[:7])
	cipher2 = DES.new(b'\x00' + des_key[7:14])
	#encode the flag with triple-DES
	flag = cipher1.decrypt(cipher2.encrypt(cipher1.decrypt(unhexlify(enc_flag))))

	cursor.execute('select flag from flags where rowid = ?;', (flag_id,))
	compare_flag = cursor.fetchone()[0]
	return flag.decode() == compare_flag

