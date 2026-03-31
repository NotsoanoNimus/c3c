// Copyright (c) 2026 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// The following tests are primarily based on the Cryptographic Algorithm
//   Validation Program (CAVP) at the following link and adjacent pages:
//   https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-sigGen-FIPS205
//
module slh_dsa_tests;

bool csprng_supported @local = false;
fn void _runtime_check_csprng() @init
{
	char[64] tmp;
	if (try entropy::fill(tmp[..]))
	{
		csprng_supported = true;
	}
}


module slh_dsa_tests @test;

fn void keygen()
{
	if (!csprng_supported) return;

	SlhDsaKeyPair{128} key_pair = slh_dsa::keygen{128}()!!;
}
