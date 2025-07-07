// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license,
// a copy of which can be found in the LICENSE_STDLIB file.
//
// This is both a port of the classic C 'getopt' and 'getopt_long', with
//   an additional C3-specific way to act use command-line options.
//
//
// Original `getopt` and `getopt_long` code translated from a FreeBSD implementation:
// /*
//  * Copyright (c) 2000 The NetBSD Foundation, Inc.
//  * All rights reserved.
//  *
//  * [Original C] code is derived from software contributed to The NetBSD Foundation
//  * by Dieter Baron and Thomas Klausner.
//  */
//
module std::opt;

import libc;

import std::io;
import std::math;


const BAD_CHAR = '?';
const BAD_ARG = ':';

const char[1] PLACEHOLDER @local = {0};   // used to mark an empty 'place' value


enum OptionArgType : const inline int
{
    NO_ARGUMENT,
    REQUIRED_ARGUMENT,
    OPTIONAL_ARGUMENT,
    INCREMENTAL
}

// Used for long options - equivalent to 'struct option' in most C projects.
struct Option
{
    ZString name;
    OptionArgType has_arg;
    int* flag;
    int val;
}


// Used to control getopt_long behaviors internally.
bitstruct GetoptFlags : char @local
{
    bool permute : 0;
    bool all_args : 1;
    bool long_only : 2;
}


// While these are old and crusty, it helps C developers to be able to use familiar constructs almost 1-to-1.
int err = 1;   /* whether to print an error message */
int ind = 1;   /* index into 'args' slice */
int opt;   /* character checked for validity */
int reset;   /* reset getopt scanning pointer */
String arg;   /* argument string associated with option */


// Local variables.
char* place @local = &PLACEHOLDER[0];

int nonopt_start @local = -1;
int nonopt_end @local = -1;
int dash_prefix @local = -1;


fn void permute_args(int panonopt_start, int panonopt_end, int opt_end, String[] args) @local
{
    int cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
    String swap;

    nnonopts = panonopt_end - panonopt_start;
    nopts = opt_end - panonopt_end;
    ncycle = math::gcd(nnonopts, nopts);
    cyclelen = (opt_end - panonopt_start) / ncycle;

    for (i = 0; i < ncycle; ++i)
    {
        cstart = panonopt_end + i;
        pos = cstart;

        for (j = 0; j < cyclelen; ++j)
        {
            if (pos >= panonopt_end)
            {
                pos -= nnonopts;
            }
            else
            {
                pos += nopts;
            }

            @swap(args[pos], args[cstart]);
        }
    }
}


fn int parse_long_options(
    String[] args, ZString option_str, Option[] options, int* idx, int short_too, GetoptFlags flags
) @local
{
    char* current_dash;
    usz current_argv_len;
    int i;

    ZString has_equal;
    ZString current_argv = (ZString)place;

    switch (dash_prefix)
    {
        case 0: current_dash = "-";
        case 1: current_dash = "--";
        case 2: current_dash = "-W ";
        default: current_dash = "";
    }

    int match = -1;
    int exact_match = 0;
    int second_partial_match = 0;

    ++ind;

    if (null != (has_equal = (ZString)libc::strchr(current_argv, '=')))
    {
        // argument found (--option=arg)
        current_argv_len = has_equal.len() - current_argv.len();
        ++has_equal;
    }
    else
    {
        current_argv_len = current_argv.len();
    }

    for (i = 0; options[i].name; ++i)
    {
        /* find matching long option */
        if (current_argv != options[i].name) continue;

        if (options[i].name.len() == current_argv_len)
        {
            /* exact match */
            match = i;
            exact_match = 1;
            break;
        }

        // If this is a known short option, don't allow a partial match of a single character.
        if (short_too && current_argv_len == 1) continue;

        if (match == -1)
        {
            match = i;
        }
        else if (
            flags.long_only
            || options[i].has_arg != options[match].has_arg
            || options[i].flag != options[match].flag
            || options[i].val != options[match].val
        ) {
            second_partial_match = 1;
        }
    }

    if (!exact_match && second_partial_match)
    {
        /* ambiguous abbreviation */
        if (err) io::eprintf("getopt: ambiguous option -- %s\n", current_argv);

        opt = 0;
        return BAD_CHAR;
    }

    if (match != -1)
    {
        if (options[match].has_arg == OptionArgType.NO_ARGUMENT && has_equal)
        {
            if (err) io::eprintf("getopt: option doesn't take an argument -- %s\n", current_argv);

            // GNU sets 'opt' to 'val' regardless of flag.
            if (options[match].flag == null)
            {
                opt = options[match].val;
            }
            else
            {
                opt = 0;
            }

            return BAD_CHAR;
        }

        if (
            options[match].has_arg == OptionArgType.REQUIRED_ARGUMENT
            || options[match].has_arg == OptionArgType.OPTIONAL_ARGUMENT
        ) {
            if (has_equal)
            {
                arg = has_equal.str_view();
            }
            else if (options[match].has_arg == OptionArgType.REQUIRED_ARGUMENT)
            {
                // optional argument doesn't use next nargv
                arg = args[ind++];
            }
        }

        if (options[match].has_arg == OptionArgType.REQUIRED_ARGUMENT && (arg.ptr == null || !arg.len))
        {
            // Missing argument; leading ':' indicates no error should be generated.
            if (err) io::eprintf("option requires an argument -- %s\n", current_argv);

            // GNU sets opt to val regardless of flag
            if (options[match].flag == null)
            {
                opt = options[match].val;
            }
            else
            {
                opt = 0;
            }

            --ind;
            return BAD_ARG;
        }
    }
    else
    {
        if (short_too)
        {
            --ind;
            return -1;
        }

        if (err) io::eprintf("unknown option -- %s\n", current_argv);

        opt = 0;
        return BAD_CHAR;
    }

    if (idx) *idx = match;

    if (options[match].flag)
    {
        *(options[match].flag) = options[match].val;

        return 0;
    }
    else
    {
        return options[match].val;
    }
}


fn int getopt_internal(
    String[] args, ZString option_str, Option[] options, int* options_index, GetoptFlags flags
) @local
{
    // NOTE: This translation of getopt_internal assumes POSIXLY_CORRECT == true; therefore, all occurrences
    //   of the variable have been amended with 'true'.
    char* option_letter_list_index;
    int optchar, short_too;

    if (!option_str || !option_str[0]) return -1;

    if (option_str[0] == '-')
    {
        flags.all_args = true;
    }
    else if (true || option_str[0] == '+')
    {
        flags.permute = false;
    }

    if (option_str[0] == '+' || option_str[0] == '-') ++option_str;

    if (!ind) ind = reset = 1;
    arg = {};

    if (reset) nonopt_start = nonopt_end = -1;

    while START: (true)
    {
        if (reset || !*place)
        {
            reset = 0;

            if (ind >= args.len)
            {
                place = &PLACEHOLDER[0];

                if (nonopt_end != -1)
                {
                    permute_args(nonopt_start, nonopt_end, ind, args);

                    ind -= (nonopt_end - nonopt_start);
                }
                else if (nonopt_start != -1)
                {
                    ind = nonopt_start;
                }

                nonopt_start = nonopt_end = -1;
                return -1;
            }

            place = args[ind].ptr;

            if (place[0] != '-' || (((ZString)place).len() > 1 && !place[1] && null == libc::strchr(option_str, '-')))
            {
                // found a non-option...
                place = &PLACEHOLDER[0];

                if (flags.all_args)
                {
                    arg = args[ind++];
                    return 1;   // INORDER
                }

                if (!flags.permute) return -1;   // when no permutation wanted, stop parsing at first non-option

                // do permutation
                if (nonopt_start == -1)
                {
                    nonopt_start = ind;
                }
                else if (nonopt_end != -1)
                {
                    permute_args(nonopt_start, nonopt_end, ind, args);

                    nonopt_start = ind - (nonopt_end - nonopt_start);
                    nonopt_end = -1;
                }

                ++ind;
                continue START;   // goto START - process next argument
            }

            if (nonopt_start != -1 && nonopt_end == -1) nonopt_end = ind;

            // if there's a '-' here, '--' means this processing is finished
            if (((ZString)place).len() > 1 && place[1] && *++place == '-' && !place[1])
            {
                ++ind;
                place = &PLACEHOLDER[0];

                // found an option, so if skipped non-options, then permute
                if (nonopt_end != -1)
                {
                    permute_args(nonopt_start, nonopt_end, ind, args);
                    ind -= nonopt_end - nonopt_start;
                }

                nonopt_start = nonopt_end = -1;
                return -1;
            }
        }

        break START;
    }

    if (options.len > 0 && place != args[ind] && (*place == '-' || flags.long_only))
    {
        short_too = 0;
        dash_prefix = 0;

        if (*place == '-')
        {
            ++place;
            dash_prefix = 1;
        }
        else if (*place != ':' && null != libc::strchr(option_str, *place))
        {
            short_too = 1;
        }

        optchar = parse_long_options(args, option_str, options, options_index, short_too, flags);
        if (optchar != -1)
        {
            place = &PLACEHOLDER[0];
            return optchar;
        }
    }

    if ((optchar = (int)*place++) == (int)':'
        || (optchar == (int)'-' && *place)
        || null == (option_letter_list_index = libc::strchr(option_str, optchar))
    ) {
        if (optchar == (int)'-' && !*place) return -1;

        if (!*place) ++ind;

        if (err) io::eprintf("getopt: invalid option -- %c\n", optchar);

        opt = optchar;
        return BAD_CHAR;
    }

    if (options.len > 0 && optchar == 'W' && option_letter_list_index[1] == ';')
    {
        if (*place)
        {
            asm { nop; }   // do nothing
        }
        else if (++ind >= args.len)
        {
            place = &PLACEHOLDER[0];

            if (err) io::eprintf("getopt: option requires an argument -- %c\n", optchar);

            opt = optchar;
            return BAD_ARG;
        }
        else
        {
            place = args[ind];
        }

        dash_prefix = 2;

        optchar = parse_long_options(args, option_str, options, options_index, 0, flags);
        place = &PLACEHOLDER[0];

        return optchar;
    }

    if (*++option_letter_list_index != ':')
    {
        if (!*place) ++ind;
    }
    else
    {
        arg = {};

        if (*place)
        {
            arg = ((ZString)place).str_view();
        }
        else if (option_letter_list_index[1] != ':')
        {
            if (++ind >= args.len)
            {
                place = &PLACEHOLDER[0];

                if (err) io::eprintf("getopt: option requires an argument -- %c\n", optchar);

                opt = optchar;
                return BAD_ARG;
            }
            else
            {
                arg = args[ind];
            }
        }

        place = &PLACEHOLDER[0];
        ++ind;
    }

    return optchar;
}

fn int get(String[] args, ZString option_str) @public
    => getopt_internal(args, option_str, {}, null, {});

fn int get_long(String[] args, ZString option_str, Option[] options, int* options_index) @public
    => getopt_internal(args, option_str, options, options_index, { .permute = true });

fn int get_long_only(String[] args, ZString option_str, Option[] options, int* options_index) @public
    => getopt_internal(args, option_str, options, options_index, { .permute = true, .long_only = true });



// ========================================================================================
// ========================================================================================
// ========================================================================================
// C3-specific declarations and components.
//

faultdef
    HELP_REQUESTED, MISSING_ARGUMENT, ILLEGAL_OPTION,
    INVALID_LONGOPT
    ;


macro void? @parse(#args, ...)
{
    $if ($vacount % 3) != 0 :
        $error(`Options must be specified in triplets as "{letter}", "{longopt}", {store-ptr}.`);
    $endif

    Option[($vacount / 3)] longopts;
    var $dyn_opt_str = "";
    var $ct_argstype = (OptionArgType[$vacount / 3]){};

    $for var $argidx = 0; $argidx < $vacount; $argidx += 3 :
        var $shortname = $vaconst[$argidx];
        var $longname = $vaconst[$argidx + 1];
        var $has_arg = OptionArgType.NO_ARGUMENT;

        $if ! $longname.len :
            $error("You must specify a long name to use for each option.");
        $endif

        $if $shortname.len :
            $if ($shortname[0] < 'a' ||| $shortname[0] > 'z')
                &&& ($shortname[0] < 'A' ||| $shortname[0] > 'Z')
                &&& ($shortname[0] < '0' ||| $shortname[0] > '9')
                &&& $shortname[0] != '?' &&& $shortname[0] != '-' :
                    $error `Short-name options should match the following expression: [a-zA-Z0-9\?-]`;
            $endif
            $dyn_opt_str = $dyn_opt_str +++ $shortname[0];
        $endif

        // The third param MUST be a pointer/reference type.
        // $if !$typeof($vaarg[$argidx + 2]).nameof.ends_with("*") :
        //     $error("The parameter reference " +++ $typeof($vaarg[$argidx + 2]).nameof +++ " is not a reference type.");
        // $endif

        // Only 'bool*' types represent flags, which do not have arguments.
        $if $typeof($vaarg[$argidx + 2]).nameof != (bool*).typeid.nameof :
            $switch :
                // Furthermore, for non-flags which have arguments, they might be optional.
                $case $shortname.len >= 2 &&& $shortname[1] == '?' :
                    $has_arg = OptionArgType.OPTIONAL_ARGUMENT;
                    $dyn_opt_str = $dyn_opt_str +++ "::";
                // ... or incremental. Incremental argument types do not accept arguments.
                $case $shortname.len >= 2 &&& $shortname[1] == '+' :
                    $has_arg = OptionArgType.INCREMENTAL;
                    $if $typeof($vaarg[$argidx + 2]).nameof != (uint*).typeid.nameof :
                        $error "Incremental option '" +++ $shortname +++ "' must be of type 'uint*' (but got '"
                            +++ $typeof($vaarg[$argidx + 2]).nameof +++ "' instead).";
                    $endif
                $default :
                    $has_arg = OptionArgType.REQUIRED_ARGUMENT;
                    $dyn_opt_str = $dyn_opt_str +++ ":";
            $endswitch
        $endif

        // Track the arg type in a CT variable.
        $ct_argstype[($argidx / 3)] = $has_arg;

        // But also track the runtime longopts details.
        longopts[$argidx / 3] = { $longname, $has_arg, null, (int)($shortname[0]) };
    $endfor

    longopts[^1] = {};   // always ends with an explicit empty Option
    opt::reset = 1;   // reset getopt_long/getopt

    $echo "DynOptStr:  " +++ $dyn_opt_str;

    // This macro wraps a `getopt_long` call.
    int longopt_index;
    int optval;
    while (-1 != (optval = opt::get_long(#args, $dyn_opt_str, longopts[..], &longopt_index)))
    {
        if CT_SWITCH: (true)
        {
            io::printf("OPTVAL:  %d\n", optval);
            if ('?' == optval) return HELP_REQUESTED?;
            if (':' == optval) return ILLEGAL_OPTION?;

            $for var $argidx = 0; $argidx < $vacount; $argidx += 3 :
                var $shortname = $vaconst[$argidx];
                var $longname = $vaconst[$argidx + 1];
                var $ToType = $typeof($vaarg[$argidx + 2]);

                if ((int)($shortname[0]) == optval)
                {
                    if (longopt_index >= longopts.len - 1) return INVALID_LONGOPT?;

                    $switch ($ct_argstype[($argidx / 3)]) :
                        $case OptionArgType.NO_ARGUMENT: *($vaarg[$argidx + 2]) = true;
                        $case OptionArgType.INCREMENTAL: *($vaarg[$argidx + 2]) = *($vaarg[$argidx + 2]) + 1;
                        $default:
                            if (null != opt::arg.ptr || !opt::arg.len)
                            {
                                // Optional? Simply continue checking options.
                                if (OptionArgType.OPTIONAL_ARGUMENT == $ct_argstype[($argidx / 3)]) break CT_SWITCH;
                                // Required? Throw.
                                return MISSING_ARGUMENT?;
                            }
                            // Set the passed pointer's value.
                            String arg = opt::arg;
                            var $ArgType = $typeof($vaarg[$argidx + 2]);
                            $switch ($ArgType) :
                                $case int.typeid :
                                    *($vaarg[$argidx + 2]) = 4;
                            $endswitch
                    $endswitch

                    break CT_SWITCH;
                }
            $endfor

            // Default to not knowing the option that was presented.
            return ILLEGAL_OPTION?;
        }
    }
}
