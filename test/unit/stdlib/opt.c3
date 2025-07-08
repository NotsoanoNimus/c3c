// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license,
// a copy of which can be found in the LICENSE_STDLIB file.
//
// Provides some comprehensive tests of argument parsing capabilities with the std::opt module.
module opt_tests;

import std::opt;


faultdef TEST_FAILURE;

struct TestResult
{
    bool has_alpha;
    bool has_bravo;
    isz charlie;
    float delta;
    ZString echo;
    uint fox;
    char[3] golf;
    String[3] hotel;
    char india;
}
TestResult t;

fn void? get_india_value(String arg) @local
{
    if (arg.len < 3) return TEST_FAILURE?;

    t.india = arg[2];
}


fn bool TestResult.eq(&self, TestResult other) @operator(==)
{
    $foreach $member : TestResult.membersof :
        if (self.$eval($member.nameof) != other.$eval($member.nameof)) return false;
    $endforeach

    return true;
}


const OPTION_STR = "abc:d:e::fg:h:i:";

const LongOption[] LONGOPTS = {
    { "alpha",      NO_ARGUMENT,        null,   'a' },
    { "bravo",      NO_ARGUMENT,        null,   'b' },
    { "charlie",    REQUIRED_ARGUMENT,  null,   'c' },
    { "delta",      REQUIRED_ARGUMENT,  null,   'd' },
    { "echo",       OPTIONAL_ARGUMENT,  null,   'e' },
    { "fox",        NO_ARGUMENT,        null,   'f' },
    { "golf",       REQUIRED_ARGUMENT,  null,   'g' },
    { "hotel",      REQUIRED_ARGUMENT,  null,   'h' },
    { "india",      REQUIRED_ARGUMENT,  null,   'i' },
    {}   // sentinel
};


fn void? parse_test(String[] args) @local
{
    t = {};

    opt::@parse(
        args,
        "a" ,   "alpha",    &t.has_alpha,
        "b" ,   "bravo",    &t.has_bravo,
        "c" ,   "charlie",  &t.charlie,
        "d" ,   "delta",    &t.delta,
        "e?",   "echo",     &t.echo,
        "f+",   "fox",      &t.fox,
        "g" ,   "golf",     &t.golf,
        "h" ,   "hotel",    &t.hotel,
        "i" ,   "india",    &get_india_value,
    )!;
}

fn void? getopt_test(String[] args) @local
{
    t = {};

    int retval;
    while (-1 != (retval = opt::get(args, OPTION_STR)))
    {
        switch (retval)
        {
            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
            case 'g':
            case 'h':
            case 'i':
        }
    }
}

fn void? getopt_long_test(String[] args) @local
{
    t = {};

    int longopt_index;
    int retval;
    while (-1 != (retval = opt::get_long(args, OPTION_STR, LONGOPTS, &longopt_index)))
    {
        switch (retval)
        {
            case 'a': t.has_alpha = true;
            case 'b': t.has_bravo = true;
            case 'c': t.charlie = opt::arg.to_integer(isz.typeid)!;
            case 'd':
            case 'e':
            case 'f':
            case 'g':
            case 'h':
            case 'i':
        }
    }
}

fn void? getopt_long_only(String[] args) @local
{
    t = {};

    int longopt_index;
    int retval;
    while (-1 != (retval = opt::get_long_only(args, OPTION_STR, LONGOPTS, &longopt_index)))
    {
        switch (retval)
        {
            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
            case 'g':
            case 'h':
            case 'i':
        }
    }
}


// =====================================================================================================================
// =====================================================================================================================
// =====================================================================================================================
module opt_tests @test;

import std::opt;


fn void sanity_check_result_comparisons()
{
    TestResult left = { true, true, 123, 0.012312, "zstr", 90, {'a', 'x', 'd' }, { "str", "123", "xyz" }, 'w' };

    TestResult right = { true, true, 123, 0.012312, "zstr", 90, {'a', 'x', 'd' }, { "str", "___", "xyz" }, 'w' };
    test::@check(left != right);

    right = { true, true, 123, 0.012312, "zstr", 90, {'a', 'x', 'd' }, { "str", "123", "xyz" }, 'w' };
    test::@check(left == right);

    right = { true, false, 123, 0.012312, "zstr", 90, {'a', 'x', 'd' }, { "str", "123", "xyz" }, 'w' };
    test::@check(left != right);
}
