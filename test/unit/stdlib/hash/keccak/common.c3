// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
module keccak::tests_common;


// Should be common to every SHA-3 test module. See 'generator.py'
const String[] SIMPLE_VECTORS =
{
	"123",
	"abcdefghijklmnopqrstuvwxyz",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"The quick brown fox jumps over the lazy dog",
	"C3 is a great and acquirable language. I recommend it to everyone I know who is doing systems programming and could use something fresh that doesn't force them into strange or otherworldly syntax, just for the sake of pretentiousness.",
};


macro get_bigboi()
{
	// 100 million 'a' characters
	char[] bigboi = allocator::new_array(tmem, char, 100_000_000);
	mem::set(bigboi.ptr, 'a', bigboi.len);

	return bigboi;
}
