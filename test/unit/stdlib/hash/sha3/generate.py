#!/usr/bin/env python3
#
# Generate all SHA-3 unit test results using pycryptodome.
#
from Crypto.Hash import keccak, SHA3_224, SHA3_256, SHA3_384, SHA3_512
from Crypto.Hash import SHAKE128, SHAKE256
from Crypto.Hash import TurboSHAKE128, TurboSHAKE256
from Crypto.Hash import cSHAKE128, cSHAKE256
from Crypto.Hash import KMAC128, KMAC256

import pprint


# Some global variable used in each digest type.
simple = [
	'123',
	'abcdefghijklmnopqrstuvwxyz',
	'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
	'The quick brown fox jumps over the lazy dog',
	'C3 is a great and acquirable language. I recommend it to everyone I know who is doing systems programming and could use something fresh that doesn\'t force them into strange or otherworldly syntax, just for the sake of pretentiousness.',
]

list_of_a = ['a' for _ in range(300)]

sample_custom_strs = [
	None,
	"email signature",
	"my customization string that is a bit longer"
]


def keccak_digest(bits, data):
	# print(f"KECCAK INPUT (len: {len(data)}): '{data}'")
	k = keccak.new(digest_bits=bits)
	k.update(data.encode('utf-8'))
	return k.hexdigest()

def sha3_digest(bits, data):
	# print(f"SHA3_{bits} INPUT (len: {len(data)}): '{data}'")
	h = eval(f"SHA3_{bits}.new()")
	h.update(data.encode('utf-8'))
	return h.hexdigest()

def get_digests(levels, digest_func):
	res = dict()
	for bits in levels:
		res[bits] = {
			'empty':	digest_func(bits, ""),
			'slow':		digest_func(bits, "".join(['a'] * 100000000)),
			'simple':	[digest_func(bits, i) for i in simple],
			'a...':		[digest_func(bits, "".join(list_of_a[0:(1+i*64)])) for i in range(5)],
		}
	return res


def shake_xof(level, trim_length, data, custom = None):
	xof = eval(f"SHAKE{level}.new()")
	xof.update(data.encode('utf-8'))
	return xof.read(trim_length).hex()

def turboshake_xof(level, trim_length, data, custom = None):
	xof = eval(f"TurboSHAKE{level}.new()")
	xof.update(data.encode('utf-8'))
	return xof.read(trim_length).hex()

def cshake_xof(level, trim_length, data, custom = None):
	xof = eval(f"cSHAKE{level}.new()") if custom is None else eval(f"cSHAKE{level}.new(custom=b'{custom}')")
	xof.update(data.encode('utf-8'))
	return xof.read(trim_length).hex()

def get_xofs(levels, trim_lengths, customization_strings, xof_func):
	res = dict()
	for level in levels:
		res[level] = {
			'empty':	[xof_func(level, i, "", s) for i in trim_lengths for s in customization_strings],
			'simple':	[xof_func(level, i, j, s) for i in trim_lengths for j in simple for s in customization_strings],
			# 'slow':		[]
			'a...':		[xof_func(level, i, "".join(list_of_a[0:(1+j*64)]), s) for j in range(5) for i in trim_lengths for s in customization_strings],
		}
	return res


def kmac(level, key, trim_length, data, custom = None):
	return "abc"

def get_kmacs():
	return {}   # TODO


def main():
	res = {
		'KECCAK':		get_digests([224, 256, 384, 512], keccak_digest),
		# 'SHA3':			get_digests([224, 256, 384, 512], sha3_digest),
		# 'SHAKE':		get_xofs([128, 256], [16, 256], sample_custom_strs, shake_xof),
		# 'TURBO-SHAKE':	get_xofs([128, 256], [16, 256], sample_custom_strs, turboshake_xof),
		# 'CSHAKE':		get_xofs([128, 256], [16, 256], sample_custom_strs, cshake_xof),
		# 'KMAC':			get_kmacs(),
	}
	pprint.pprint(res)


if __name__ == "__main__":
	main()
