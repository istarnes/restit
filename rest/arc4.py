import hashlib

def _xor_idstr(data, encrypt):
	lastc = 51
	cnt = 126
	r = []
	for i in range(len(data)):
		r.append(chr(ord(data[i]) ^ lastc ^ ((cnt*7)%256) ^ (11 * (2**(lastc % 5)))  ))
		if encrypt:
			lastc = lastc ^ ord(data[i])
		else:
			lastc = lastc ^ ord(r[i])
	return r

def _rc4_round(data, key, encrypt, discard):
	# setup sbox
	x = 0
	box = range(256)
	for i in range(256):
		x = (x + box[i] + ord(key[i % len(key)])) % 256
		box[i], box[x] = box[x], box[i]
	x = 0
	y = 0
	out = []

	# discard first rounds
	for i in range(discard):
		x = (x + 1) % 256
		y = (y + box[x]) % 256
		box[x], box[y] = box[y], box[x]
	
	# pre process
	if encrypt:
		data = _xor_idstr(data, encrypt)
	else:
		data.reverse()
	
	# rc4 crypt
	for char in data:
		x = (x + 1) % 256
		y = (y + box[x]) % 256
		box[x], box[y] = box[y], box[x]
		out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
	
	# post process
	if encrypt:
		out.reverse()
	else:
		out = _xor_idstr(out, encrypt)

	return out
	
def crypt(data, key, encrypt):
	key = hashlib.md5(key).digest()

	data = list(data)
	out = _rc4_round(data, key, encrypt, encrypt and 871 or 917)
	out = _rc4_round(out, key, encrypt, encrypt and 917 or 871)

	return ''.join(out)
