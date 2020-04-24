
#!/usr/bin/env python3
from enochecker import *

from binascii import unhexlify, hexlify
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Util.number import long_to_bytes, bytes_to_long


key = RSA.importKey(open('checker.privkey','r').read())

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
    noise_count = 0
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
                content = b'receive:' + self.flag.encode() + (b':%d' % self.flag_round)
                signature = hex(key.sign(content, 1)[0])[2:].encode()
                input_data = content + b' ' + signature

                conn = self.connect()
                expect_command_prompt(conn)
                conn.write(input_data + b"\n")
                ret_id = expect_command_prompt(conn)
                print(ret_id)
                ret_id = int(ret_id .split(b'id:')[1].split(b'\n')[0].decode())
                conn.close()

                self.team_db[self.flag] = ret_id    


        except EOFError:
            raise OfflineException("Encountered unexpected EOF")
        except UnicodeError:
            self.debug("UTF8 Decoding-Error")
            raise BrokenServiceException("Fucked UTF8")

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
                service_id = self.team_db[self.flag]
                print(service_id, type(service_id))
                expect_command_prompt(conn)
                conn.write(b"send_flag_ids:%d\n" % self.flag_round)
                ids = expect_command_prompt(conn)[:-1].decode()
                self.debug(ids)
                ids = [int(i) for i in ids.split(":")]

                print(ids)
                if not service_id in ids:
                    conn.close()
                    raise BrokenServiceException("id not found in service")

                conn.write(b"send_flag:%d\n" % service_id)
                res = expect_command_prompt(conn).decode()
                res = res.split("b'")[1].split("'")[0]
                enc_des_key, enc_flag = res.split(':')
                des_key = long_to_bytes(pow(int(enc_des_key,16), key.d, key.n))

                cipher1 = DES.new(b'\x00' + des_key[:7])
                cipher2 = DES.new(b'\x00' + des_key[7:14])
                #encode the flag with triple-DES
                flag = cipher1.decrypt(cipher2.encrypt(cipher1.decrypt(unhexlify(enc_flag))))
                flag = flag.split(b"\0")[0].decode()
                print(flag, self.flag)
                if not flag == self.flag:
                    raise BrokenServiceException("Resulting flag was found to be incorrect")

        except EOFError:
            raise OfflineException("Encountered unexpected EOF")
        except UnicodeError:
            self.debug("UTF8 Decoding-Error")
            raise BrokenServiceException("Fucked UTF8")

    def putnoise(self):  # type: () -> None
        """
        This method stores noise in the service. The noise should later be recoverable.
        The difference between noise and flag is, tht noise does not have to remain secret for other teams.
        This method can be called many times per round. Check how often using self.flag_idx.
        On error, raise an EnoException.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        self.team_db["noise"] = self.noise

    def getnoise(self):  # type: () -> None
        """
        This method retrieves noise in the service.
        The noise to be retrieved is inside self.flag
        The difference between noise and flag is, tht noise does not have to remain secret for other teams.
        This method can be called many times per round. Check how often using flag_idx.
        On error, raise an EnoException.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        try:
            assert_equals(self.team_db["noise"], self.noise)
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
    return conn.readline_expect(b'command:',b'command:').split(b'command')[0]

app = CryStoreChecker.service  # This can be used for uswgi.
if __name__ == "__main__":
    run(CryStoreChecker)
    # Example params could be: [StoreFlag localhost ENOFLAG 1 ENOFLAG 50 1]
    # exit(ExampleChecker(port=1337).run())