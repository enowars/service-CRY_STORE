
#!/usr/bin/env python3
from enochecker import *

from binascii import unhexlify, hexlify
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha256
import random

from crypto import decrypt, encrypt, sign, verify

private_key = RSA.importKey(open('checker.privkey','r').read())

class CryStoreChecker(BaseChecker):
	"""
	Change the methods given here, then simply create the class and .run() it.
	Magic.
	A few convenient methods and helpers are provided in the BaseChecker.
	ensure_bytes ans ensure_unicode to make sure strings are always equal.
	As well as methods:
	self.connect() connects to the remote server.
	self.get and self.post request from http.
	self.team_db is a dict that stores its contents to filesystem. (call .persist() to make sure)
	self.readline_expect(): fails if it's not read correctly
	To read the whole docu and find more goodies, run python -m pydoc enochecker
	(Or read the source, Luke)
	"""

	flag_count = 1
	noise_count = 1
	havoc_count = 0
	service_name = "cry_store"
	port = (
		9122
	)  # The port will automatically be picked up as default by self.connect and self.http.

	def putflag(self):  # type: () -> None
		"""
			This method stores a flag in the service.
			In case multiple flags are provided, self.flag_idx gives the appropriate index.
			The flag itself can be retrieved from self.flag.
			On error, raise an Eno Exception.
			:raises EnoException on error
			:return this function can return a result if it wants
					if nothing is returned, the service status is considered okay.
					the preferred way to report errors in the service is by raising an appropriate enoexception
		"""
		try:
			if self.flag_idx == 0:
				if self.team not in self.global_db:
					self.get_pubkey()
				key = RSA.import_key(self.global_db[self.team])

				content = 'flag %s %d' % (encrypt(self.flag, key), self.flag_round)
				signature = sign(content)

				input_data = ('receive %s %s' % (content, signature)).encode()

				conn = self.connect()
				expect_command_prompt(conn)
				conn.write(input_data + b"\n")
				ret_id = expect_command_prompt(conn)
				if sha256(self.flag.encode()).hexdigest() != ret_id:
					raise BrokenServiceException('Returned wrong hash')
				conn.close()

				self.team_db[self.flag] = ret_id	

		except EOFError:
			raise OfflineException("Encountered unexpected EOF")
		except UnicodeError:
			self.debug("UTF8 Decoding-Error")
			raise BrokenServiceException("Fucked UTF8")
	
	def get_pubkey(self):
		conn = self.connect()
		expect_command_prompt(conn)
		conn.write(b"send_pubkey\n")
		ret_value = expect_command_prompt(conn).decode()
		try:
			key = RSA.import_key(ret_value)
		except ValueError:
			raise BrokenServiceException('Invalid public key')
		conn.close()

		#store pubkey as string
		self.team_db['pubkey'] = ret_value

	def getflag(self):  # type: () -> None
		"""
		This method retrieves a flag from the service.
		Use self.flag to get the flag that needs to be recovered and self.round to get the round the flag was placed in.
		On error, raise an EnoException.
		:raises EnoException on error
		:return this function can return a result if it wants
				if nothing is returned, the service status is considered okay.
				the preferred way to report errors in the service is by raising an appropriate enoexception
		"""
		try:
			if self.flag_idx == 0:
				conn = self.connect()
				expect_command_prompt(conn)
				conn.write(b"send flag %d\n" % self.flag_round)
				ciphertext = expect_command_prompt(conn).decode()
				flag = decrypt(ciphertext, privkey = private_key)
				if not flag == self.flag:
					#error might be because of updated public key, so renew it
					self.get_pubkey()
					raise BrokenServiceException("Resulting flag was found to be incorrect")

		except EOFError:
			raise OfflineException("Encountered unexpected EOF")
		except UnicodeError:
			self.debug("UTF8 Decoding-Error")
			raise BrokenServiceException("Fucked UTF8")

	def putnoise(self):  # type: () -> None
		"""
		This method stores noise in the service. The noise should later be recoverable.
		The difference between noise and flag is, that noise does not have to remain secret for other teams.
		This method can be called many times per round. Check how often using self.flag_idx.
		On error, raise an EnoException.
		:raises EnoException on error
		:return this function can return a result if it wants
				if nothing is returned, the service status is considered okay.
				the preferred way to report errors in the service is by raising an appropriate enoexception
		"""
		try:
			if self.flag_idx == 0:
				joke = random.choice(open('jokes','r').read().split('\n\n'))
				joke_hex = hexlify(joke.encode()).decode()
				self.team_db['noise'] = joke

				content = 'joke %s %d' % (joke_hex, self.flag_round)
				signature = sign(content)

				input_data = ('receive %s %s' % (content, signature)).encode()

				conn = self.connect()
				expect_command_prompt(conn)
				conn.write(input_data + b"\n")
				ret_id = expect_command_prompt(conn)
				if sha256(joke.encode()).hexdigest() != ret_id:
					raise BrokenServiceException('Returned wrong hash')
				conn.close()
		except EOFError:
			raise OfflineException("Encountered unexpected EOF")
		except UnicodeError:
			self.debug("UTF8 Decoding-Error")
			raise BrokenServiceException("Fucked UTF8")

	def getnoise(self):  # type: () -> None
		"""
		This method retrieves noise in the service.
		The noise to be retrieved is inside self.flag
		The difference between noise and flag is, that noise does not have to remain secret for other teams.
		This method can be called many times per round. Check how often using flag_idx.
		On error, raise an EnoException.
		:raises EnoException on error
		:return this function can return a result if it wants
				if nothing is returned, the service status is considered okay.
				the preferred way to report errors in the service is by raising an appropriate enoexception
		"""
		try:
			if self.flag_idx == 0:
				conn = self.connect()
				expect_command_prompt(conn)
				conn.write(b"send joke %d\n" % self.flag_round)
				joke_hex = expect_command_prompt(conn).decode()
				joke = unhexlify(joke_hex).decode()
				if joke != self.team_db["noise"]:
					raise BrokenServiceException("I didn't get the joke.")
		except EOFError:
			raise OfflineException("Encountered unexpected EOF")
		except UnicodeError:
			self.debug("UTF8 Decoding-Error")
			raise BrokenServiceException("Fucked UTF8")
		except KeyError:
			raise BrokenServiceException("Noise not found!")

	def havoc(self):  # type: () -> None
		"""
		This method unleashes havoc on the app -> Do whatever you must to prove the service still works. Or not.
		On error, raise an EnoException.
		:raises EnoException on Error
		:return This function can return a result if it wants
				If nothing is returned, the service status is considered okay.
				The preferred way to report Errors in the service is by raising an appropriate EnoException
		"""
		self.info("I wanted to inform you: I'm  running <3")
		self.http_get(
			"/"
		)  # This will probably fail, depending on what params you give the script. :)

	def exploit(self):
		"""
		This method was added for CI purposes for exploits to be tested.
		Will (hopefully) not be called during actual CTF.
		:raises EnoException on Error
		:return This function can return a result if it wants
				If nothing is returned, the service status is considered okay.
				The preferred way to report Errors in the service is by raising an appropriate EnoException
		"""
		pass

def expect_command_prompt(conn):
	return conn.readline_expect(b'command: ',b'command: ').split(b'command')[0] # need colon and space in split?

app = CryStoreChecker.service  # This can be used for uswgi.
if __name__ == "__main__":
	run(CryStoreChecker)
	# Example params could be: [StoreFlag localhost ENOFLAG 1 ENOFLAG 50 1]
	# exit(ExampleChecker(port=1337).run())
