// Copyright (c) 2021-2023 Christoffer Lerno. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
module std::os::env;
import std::io::path, libc, std::os;

<*
 @param [in] name
 @require name.len > 0
 @return? NOT_FOUND
*>
fn String? get_var(Allocator allocator, String name) => @pool()
{

	$switch:
	$case env::LIBC && !env::WIN32:
		ZString val = libc::getenv(name.zstr_tcopy());
		return val ? val.copy(allocator) : NOT_FOUND?;
	$case env::WIN32:
		// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getenvironmentvariable
		const usz BUFSIZE = 1024;
		WString buff = (WString)tcalloc(BUFSIZE * 2 + 2);
		WString wstr = name.to_temp_wstring()!;
		usz len = win32::getEnvironmentVariableW(wstr, buff, BUFSIZE);
		if (len == 0) return NOT_FOUND?;
		if (len > BUFSIZE)
		{
			buff = (WString)tmalloc(len * 2 + 2);
			win32::getEnvironmentVariableW(wstr, buff, (Win32_DWORD)len);
		}
		return string::from_wstring(allocator, buff);
	$default:
		return "";
	$endswitch
}

fn String? tget_var(String name)
{
	return get_var(tmem, name);
}

<*
 @param [in] name
 @param [in] value
 @require name.len > 0
*>
fn bool set_var(String name, String value, bool overwrite = true) => @pool()
{
	$switch:
	$case env::WIN32:
		WString wname = name.to_temp_wstring()!!;
		if (!overwrite)
		{
			Char16[8] buff;
			if (win32::getEnvironmentVariableW(wname, &buff, 8) > 0) return true;
		}
		// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setenvironmentvariable
		return (win32::setEnvironmentVariableW(wname, value.to_temp_wstring()) ?? 1) == 0;
	$case env::LIBC && !env::WIN32:
		return libc::setenv(name.zstr_tcopy(), value.zstr_tcopy(), (int)overwrite) == 0;
	$default:
		return false;
	$endswitch
}

<*
Returns the current user's home directory.
*>
fn String? get_home_dir(Allocator allocator)
{
	String home;
	$if !env::WIN32:
		home = "HOME";
	$else
		home = "USERPROFILE";
	$endif
	return get_var(allocator, home);
}


<*
 Returns the current user's config directory.
*>
fn Path? get_config_dir(Allocator allocator) => @pool()
{
	$if env::WIN32:
		return path::new(allocator, tget_var("AppData"));
	$else
		$if env::DARWIN:
			String home_dir = tget_var("HOME")!;
			const DIR = "Library/Application Support";
		$else
			String? config_path = tget_var("XDG_CONFIG_HOME");
			if (try config_path && config_path.len > 0) return path::new(allocator, config_path);
			String home_dir = tget_var("HOME")!;
			const DIR = ".config";
		$endif
		return path::temp(home_dir).append(allocator, DIR);
	$endif
}


<*
 @param [in] name
 @require name.len > 0
*>
fn bool clear_var(String name) => @pool()
{
	$switch:
	$case env::WIN32:
		WString wname = name.to_temp_wstring()!!;
		return win32::setEnvironmentVariableW(wname, null) == 0;
	$case env::LIBC && !env::WIN32:
		return libc::unsetenv(name.zstr_tcopy()) == 0;
	$default:
		return false;
	$endswitch
}

fn String? executable_path()
{
	$if env::DARWIN:
		return darwin::executable_path();
	$else
		return NOT_FOUND?;
	$endif
}
