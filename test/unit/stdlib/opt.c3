// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license,
// a copy of which can be found in the LICENSE_STDLIB file.
//
// Provides some comprehensive tests of argument parsing capabilities with the std::opt module.
module opt_tests;

import std::opt;
import std::io;


faultdef TEST_FAILURE;

struct TestResult (Printable)
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
int longopt_index, golf_index, hotel_index;

fn void? get_india_value(String arg)
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

fn usz? TestResult.to_format(&self, Formatter* f) @dynamic
    => f.printf(
        "[A(%s) B(%s) C(%s) D(%s) E(%s) F(%s) G(%s) H(%s) I(%s)]",
        self.has_alpha, self.has_bravo, self.charlie, self.delta, self.echo, self.fox, self.golf, self.hotel, self.india
    )!;


fn void fresh()
{
    opt::@reset();
    t = {};
    longopt_index = golf_index = hotel_index = 0;
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


fn void? parse_test(String[] args) =>
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

fn void? getopt_test(String[] args)
{
    int retval;
    while (-1 != (retval = opt::get(args, OPTION_STR))) common_switch(retval)!;
}

fn void? getopt_long_test(String[] args)
{
    int retval;
    while (-1 != (retval = opt::get_long(args, OPTION_STR, LONGOPTS, &longopt_index))) common_switch(retval)!;
}

fn void? getopt_long_only_test(String[] args)
{
    int retval;
    while (-1 != (retval = opt::get_long_only(args, OPTION_STR, LONGOPTS, &longopt_index))) common_switch(retval)!;
}

fn void? common_switch(int retval) @local
{
    io::printf("[consume opt retval] ==> '%d' ... ", retval);

    switch (retval)
    {
        case ':':
        case '?':
            io::printn("(MISSING_ARGUMENT)");
            return opt::MISSING_ARGUMENT?;

        case 'a': t.has_alpha = true; io::printn("(alpha)");
        case 'b': t.has_bravo = true; io::printn("(bravo)");
        case 'c': t.charlie = opt::arg.to_integer(isz.typeid)!; io::printn("(charlie)");
        case 'd': t.delta = opt::arg.to_float()!; io::printn("(delta)");
        case 'e': if (opt::arg.ptr != null) t.echo = (ZString)opt::arg.ptr; io::printn("(echo)");
        case 'f': ++t.fox; io::printn("(fox)");

        case 'g':
            io::printn("(golf)");
            if (golf_index >= t.golf.len) return opt::OUT_OF_BOUNDS?;
            if (opt::arg.len == 0 || !opt::arg.ptr) return opt::MISSING_ARGUMENT?;
            t.golf[golf_index] = opt::arg[0];
            ++golf_index;

        case 'h':
            io::printn("(hotel)");
            if (hotel_index >= t.hotel.len) return opt::OUT_OF_BOUNDS?;
            if (opt::arg.len == 0 || !opt::arg.ptr) return opt::MISSING_ARGUMENT?;
            t.hotel[hotel_index] = opt::arg;
            ++hotel_index;

        case 'i':
            io::printn("(india)");
            if (opt::arg.len > 0 && *opt::arg.ptr)
            {
                t.india = opt::arg[0];
            }
            else
            {
                return opt::MISSING_ARGUMENT?;
            }
    }
}


// =====================================================================================================================
// =====================================================================================================================
// =====================================================================================================================
module opt_tests @test;

import std::opt;
import std::io;

enum CallType : const inline int @local
{
    SHORT,
    LONG,
    LONG_ONLY,
}


macro void? @run(CallType $test_type, #args, #expected) @local
{
    String[] args;
    TestResult expected;

    fresh();   // fresh test
    // 'args' is always prepended with a dummy value to mimic the ever-present '$0'
    args = { "program-name" , ...(String[])#args };   
    expected = #expected;

    io::printn("\n=== NEW RUN ===");
    foreach(i, a : args) io::printf("---> ARG[%d]: %s\n", i, a);

    $switch ($test_type) :
        $case SHORT : getopt_test(args)!;
        $case LONG : getopt_long_test(args)!;
        $case LONG_ONLY : getopt_long_only_test(args)!;

        $default : $error "Invalid test type. Valid types are 'SHORT', 'LONG', or 'LONG_ONLY'.";
    $endswitch

    test::@check(t == expected, "\r\n\tExpected: %s\r\n\tActual t: %s", expected, t);
}


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


fn void simple_short_opts()
{
    // Booleans/Flags.
    @run(SHORT, { "-a", "-c", "1234" }, { .has_alpha = true, .has_bravo = false, .charlie = 1234 })!!;
    @run(SHORT, { "-ac", "1234" }, { .has_alpha = true, .has_bravo = false, .charlie = 1234 })!!;
    @run(SHORT, { "-bc", "888" }, { .has_alpha = false, .has_bravo = true, .charlie = 888 })!!;
}

fn void simple_short_opts_failures()
{
    // Missing arguments.
    // @run(SHORT, { "-a", "-c", "1234" }, { .has_alpha = true, .has_bravo = false, .charlie = 1234 })!!;
    // @run(SHORT, { "-ac", "1234" }, { .has_alpha = true, .has_bravo = false, .charlie = 1234 })!!;
    // @run(SHORT, { "-bc", "888" }, { .has_alpha = false, .has_bravo = true, .charlie = 888 })!!;
}