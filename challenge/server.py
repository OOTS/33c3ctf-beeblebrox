#!/usr/bin/python3

from socketserver import StreamRequestHandler, ThreadingTCPServer
from hashlib import sha256
import base64
import random


# CONSTANTS
MODULUS = 16536507737844787892641865661863462397631522150212024091004887310964200827020178668239882145253630803151168956393779505928808506196120351189499349932786784708370138096658243543880715379147242259129181920278789039223128954389992858894196591733488967188941263924281855801225333337971369346979277183346095695839072573619497479683662969453719477093511680505106353869706149218300987922266699186873224155102741256320112045419277230096733452241250195932716682446395562027663309040452928460169789196285753228735312068600940483519875428506460333422009758551679944423660319026521184358407797626088473071231220477237579974133813
S = 2279870349089594676078131957223427526372940435342871764510345335207700176127662830938770929147412047169033459649625173227912122654011065802421796926972585798820409017163625434862756489760448381608543257498933257519457833349391617168881001250072857294234191917642557763462668502951731492599248590640073798156146984110885838926659848552808727770775032147602500322865941084978965993286193260974797123500037313973609102107825877355293422553505328529637538623308810977388182025133271286463800018303412599528683244178480216737543334821269172129558292624827118889631230859505678242114445252685966124989815656101539186906614
SEPARATOR = ";"
TARGET_MSG = "I, Zaphod Beeblebrox, hereby resign from my office as president of the Galaxy."
LISTEN_ON = ('0.0.0.0', 2048)
PROOF_OF_WORK_HARDNESS = 2**20
TIMEOUT = 40
if __name__ == "__main__":
	FLAG = open("flag.txt", 'r').read()
	P = int(open("P.txt", "r").read())
	Q = int(open("Q.txt", "r").read())
	# Note: P and Q are strong primes
	PHI = (P-1)*(Q-1)
	
	# SANITY CHECKS
	assert(MODULUS == P * Q)
	assert(S < MODULUS)

# CODE
def encode(i, length):
	i = i.to_bytes(length, 'little')
	return base64.b64encode(i)

def decode(i, min, max):
	i = base64.b64decode(i)
	i = int.from_bytes(i, 'little')
	if i < min:
		raise ValueError("i too small")
	if i >= max:
		raise ValueError("i too large")
	return i

def hash(msg, ctr):
	h = sha256(msg.encode('ASCII') + ctr.to_bytes(4, 'little'))
	h = h.digest()
	h = h[0:16]
	h = int.from_bytes(h, 'little')
	return h

def is_prime(n, c):
	
	if n <= 1: return False
	if n == 2 or n == 3: return True
	if n % 2 == 0: return False
	
	for _ in range(c):
		a = random.randrange(1, n)
		if not pow(a, n-1, n) != 1:
			return False
	
	return True

def extended_gcd(a, b):
	
	def _egcd(a, b):
		if a % b == 0:
			return b, 0, 1
		else:
			g, s, t = _egcd(b, a % b)
			assert(s * b + t * (a % b) == g)
			return g, t, s - t * (a // b)
	
	if a < b:
		g, d, c = _egcd(b, a)
	else:
		g, c, d = _egcd(a, b)
	
	return g, c, d

def modinv(a, m):
	
	""" compute the modular inverse of a modulo m.
	Raises an error if a does not have an inverse, (i.e. gcd(a, m) != 1)."""
	
	g, s, _ = extended_gcd(a, m)
	if g != 1:
		raise ValueError("cannot compute modular inverse of {} modulo {}. common divisor: {}".format(a, m, g))
	return s % m

def random_string(length = 10):
	characters = [chr(i) for i in range(ord('a'), ord('z') + 1)]
	characters += [chr(i) for i in range(ord('A'), ord('Z') + 1)]
	characters += [chr(i) for i in range(ord('0'), ord('9') + 1)]
	result = ""
	for _ in range(length):
		result += random.choice(characters)
	return result

def proof_of_work_okay(task, solution):
	h = sha256(task.encode('ASCII') + solution.to_bytes(4, 'little')).digest()
	return int.from_bytes(h, 'little') < 1/PROOF_OF_WORK_HARDNESS * 2**256

class GhrRequestHandler(StreamRequestHandler):
	
	timeout = TIMEOUT
	
	def handle(self):
		self.send_msg("Hi Baby!")
		self.send_msg("Ever met someone from another planet? ;)")
		self.send_msg("I certainly have never met a hot babe like you out there in this little galaxy!")
		self.send_msg("I'm actually the president of the universe, you know?")
		challenge = random_string()
		self.send_msg("Want an autograph? ({})".format(challenge))
		
		
		query = self.recv_msg()
		while query != "Resign!\n" and query != "":
			proof_of_work, msg, ctr = map(str.strip, query.split(SEPARATOR))
			proof_of_work = decode(proof_of_work, 0, 2**32)
			if not proof_of_work_okay(challenge, proof_of_work):
				self.send_msg("Nope")
				return
			ctr = decode(ctr, 0, 2**32)
			h = hash(msg, ctr)
			if msg == TARGET_MSG or not is_prime(h, 128):
				self.send_msg("Sorry, I can't sign that.")
			else:
				exponent = modinv(h, PHI)
				signature = pow(S, exponent, MODULUS)
				self.send_msg("Here you are, darling!")
				self.send_msg(encode(signature, 256))
			
			challenge = random_string()
			self.send_msg("Want another one? ;) ({})".format(challenge))
			query = self.recv_msg()
		
		if query == "Resign!\n":
			challenge = random_string()
			self.send_msg("Why? ({})".format(challenge))
			response = self.recv_msg()
			proof_of_work, msg, ctr, signature = map(str.strip, response.split(SEPARATOR))
			proof_of_work = decode(proof_of_work, 0, 2**32)
			if proof_of_work_okay(challenge, proof_of_work):
				ctr = decode(ctr, 0, 2**32)
				signature = decode(signature, 2, MODULUS)
				h = hash(TARGET_MSG, ctr)
				if msg == TARGET_MSG and pow(signature, h, MODULUS) == S and is_prime(h, 128):
					self.send_msg("Okay, I give up :(")
					self.send_msg("Here's your flag: " + FLAG)
				else:
					self.send_msg("No.")
			else:
				self.send_msg("Nope")
				return
		
	def send_msg(self, msg):
		if not (isinstance(msg, bytes) or isinstance(msg, bytearray)):
			msg = msg.encode('ASCII')
		self.wfile.write(msg + b"\n")
		
	def recv_msg(self):
		return self.rfile.readline(512).decode('ASCII')
	
	def finish(self):
		try:
			self.send_msg("Goodbye!\n")
		finally:
			super().finish()

class GhrServer(ThreadingTCPServer):
	
	def __init__(self, LISTEN_ON):
		super().__init__(LISTEN_ON, GhrRequestHandler)
		self.allow_reuse_address = True


if __name__ == "__main__":
	s = GhrServer(LISTEN_ON)
	s.serve_forever()

