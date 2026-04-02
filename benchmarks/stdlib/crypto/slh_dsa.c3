// Copyright (c) 2026 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
module slh_dsa_bench @private;

import std::crypto;

SlhDsaKeyPair{128} test_keyring_128;

fn void initialize_bench() @init
{
	set_benchmark_warmup_iterations(1);
	set_benchmark_max_iterations(8 + 1);
	test_keyring_128 = slh_dsa::keygen{128}()!!;
}


// =======================================================================================
module slh_dsa_bench @benchmark;

import std::crypto;

fn void sign_128()
{
	char[255] msg;
	char[32] context;
	entropy::fill(msg[..])!!;
	entropy::fill(context[..])!!;

	@start_benchmark();
		slh_dsa::sign{128}(tmem, test_keyring_128.privkey, msg[..], context: context[..], hedged: false)!!;
	@end_benchmark();
}
