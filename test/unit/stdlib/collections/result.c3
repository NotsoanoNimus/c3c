// Copyright (c) 2026 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
module std::collections::result_test @test;

import std::collections;
import std::io;

fn void test_equivalence_ok()
{
	Result{int} x = ok(7);
	Result{double} y = ok(7.0000);
	Result{int} z = ok(900);
	Result{int} a = err(NOT_FOUND);
	test::@check(x == x);
	test::@check(x == y);
	test::@check(x != z);
	test::@check(x != a);
}

fn void test_equivalence_err()
{
	Result{int} x = err(NOT_IMPLEMENTED);
	Result{double} y = err(NOT_IMPLEMENTED);
	Result{int} z = err(NOT_FOUND);
	Result{int} a = ok(7);
	test::@check(x == x);
	test::@check(x == y);
	test::@check(x != z);
	test::@check(x != a);
}

fn void test_is_ok()
{
	Result{int} x = ok(7);
	test::@check(x.is_ok());
	test::@check(x.ok().get()!! == 7);
	test::@check(x.unwrap() == 7);
}

fn void test_is_ok_and()
{
	Result{int} x = ok(256);
	Result{int} y = err(NOT_IMPLEMENTED);
	test::@check(x.is_ok_and(fn (p) => p < 1000));
	test::@check(!x.is_ok_and(fn (p) => p > 1000));
	test::@check(!y.is_ok_and(fn (p) => p > 0));
}

fn void test_is_err()
{
	Result{int} x = err(io::EOF);
	test::@check(x.is_err());
	test::@check(x.err().get()!! == io::EOF);
	test::@check(x.unwrap_err() == io::EOF);
}

fn void test_is_err_and()
{
	Result{int} x = err(NOT_IMPLEMENTED);
	Result{int} y = ok(256);
	test::@check(x.is_err_and(fn (p) => p == NOT_IMPLEMENTED));
	test::@check(!x.is_err_and(fn (p) => p == io::EOF));
	test::@check(!y.is_err_and(fn (p) => p != io::EOF));
}

fn void test_ok()
{
	Result{int} x = ok(200);
	test::@check(x.ok().get()!! == 200);
	test::@check(x.unwrap() == 200);
	// attempting to unwrap a faulty Result as 'ok' should yield a NOT_FOUND error (see: Maybe)
	Result{int} y = err(NO_MORE_ELEMENT);
	test::@error(y.ok().get(), NOT_FOUND);
	test::@error(y.unwrap($panic: false), result::EXPECTED_VALUE);
}

fn void test_err()
{
	Result{int} x = err(NO_MORE_ELEMENT);
	test::@check(x.err().get()!! == NO_MORE_ELEMENT);
	// attempting to unwrap an ok Result as 'err' should yield a NOT_FOUND error (see: Maybe)
	Result{int} y = ok(200);
	test::@error(y.err().get(), NOT_FOUND);
}

fn void test_unwrap()
{
	Result{int} x = ok(123);
	test::@check(x.unwrap() == 123);
	test::@check(x.unwrap($panic: false)!! == 123);
	Result{int} y = err(NOT_IMPLEMENTED);
	// test::@check(y.unwrap() == 123);   // <--- will crash as expected when uncommented
	test::@error(y.unwrap($panic: false), result::EXPECTED_VALUE);
}

fn void test_map()
{
	Result{String} in = ok("1234");
	test::@check(in.map(fn int (String x) => x.to_integer(int)!!) == ok((int)1234));
	Result{String} faulty = err(NOT_IMPLEMENTED);
	test::@check(faulty.map(fn int (String x) => x.to_integer(int)!!) == err{int}(NOT_IMPLEMENTED));
}

fn void test_map_or()
{
	Result{int} x = ok(123);
	test::@check(x.map_or(fn int (int c) => c + 20, -100) == 143);
	Result{int} y = err(NOT_IMPLEMENTED);
	test::@check(y.map_or(fn int (int c) => c + 20, -100) == -100);
}

fn void test_map_or_else()
{
	Result{int} x = ok(123);
	test::@check(x.map_or_else(fn String (int c) => "all good", fn String (fault c) => "not good") == "all good");
	Result{int} y = err(NOT_IMPLEMENTED);
	test::@check(y.map_or_else(fn String (int c) => "all good", fn String (fault c) => "not good") == "not good");
}
