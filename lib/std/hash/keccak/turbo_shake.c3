// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// For KT and TurboSHAKE hashes, see: https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/
//
//   TurboSHAKE allows the user to specify their own DELIMITER value at runtime.
//
//   This should remain a separate module, even thoguh it's almost the same as SHAKE, lest this
//   become very confusing to maintainers. It's not worth folding this into SHAKE to save a few
//   extra lines.
//
module std::hash::sha3::turbo_shake;

import std::hash::sha3::shake;

macro typeid turbo($security_level)
{
	return shake::shake($security_level, $rounds: 12);
}

macro char[*] xof($security_level, $outlen_bytes, char[] data, char delimiter = 0x1F)
{
	char[$outlen_bytes] into;

	$typefrom(shake::shake($security_level, $rounds: 12)) s @noinit;
	defer s.wipe();
	s.init(delimiter);
	s.absorb(data);
	s.pad();
	s.squeeze(into[..]);

	return into;
}

alias TurboShake128 = $typefrom(turbo(128));
alias TurboShake256 = $typefrom(turbo(256));

macro char[*] hash_128($outlen_bytes, char[] data, char delimiter = 0x1F) => xof(128, $outlen_bytes, data, delimiter: delimiter) @inline;
macro char[*] hash_256($outlen_bytes, char[] data, char delimiter = 0x1F) => xof(256, $outlen_bytes, data, delimiter: delimiter) @inline;
