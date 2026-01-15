// Copyright (c) 2026 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
module std::collections::result;

import std::collections::maybe;

faultdef EMPTY_FAULT @local;
faultdef EXPECTED_VALUE, EXPECTED_ERROR;

alias OkPredicateFn @local @generic(TypeT) = fn bool (TypeT);
alias ErrPredicateFn @local = fn bool (fault);

struct Result @generic(TypeT)
{
	TypeT value;
	fault error;
}

<*
 @require $defined(self.value == other.value) : "The inner values of the result types must be equatable."
*>
macro bool Result.eq(&self, other) @operator(==) => (self.is_ok() && self.value == other.value) || (self.is_err() && self.error == other.error);

macro ok(value) @builtin => (Result{$typeof(value)}){ .value = value, .error = EMPTY_FAULT };
macro err(fault error) @generic(TypeT) @builtin => (Result{TypeT}){ .error = error };

macro Maybe{TypeT} Result.ok(&self) => self.is_ok() ? maybe::some{TypeT}(self.value) : maybe::NONE{TypeT};
macro bool Result.is_ok(&self) => self.error == EMPTY_FAULT;
macro bool Result.is_ok_and(&self, OkPredicateFn{TypeT} func) => self.is_ok() && (func(self.value) == true);

macro Maybe{fault} Result.err(&self) => self.is_err() ? maybe::some{fault}(self.error) : maybe::NONE{fault};
macro bool Result.is_err(&self) => self.error != EMPTY_FAULT;
macro bool Result.is_err_and(&self, ErrPredicateFn func) => self.is_err() && (func(self.error) == true);

macro TypeT? Result.expect(&self, String message = "", bool panic = true)
{
	if (self.is_ok()) return self.value;
	return panic ? abort(message) : EXPECTED_VALUE?;
}
macro fault? Result.expect_err(&self, String message = "", bool panic = true)
{
	if (self.is_err()) return self.error;
	return panic ? abort(message) : EXPECTED_ERROR?;
}

macro Result.unwrap(&self, bool $panic = true)
	=> self.ok().get() ?? ($panic ??? abort("Result unwrapped error: %s", self.error) : EXPECTED_VALUE?);
macro TypeT Result.unwrap_or(&self, TypeT _default = {}) => self.unwrap($panic: false) ?? _default;
<*
 @require $typeof(func).returns == TypeT : "The alternative computation function must return a value of the wrapped type."
*>
macro TypeT Result.unwrap_or_else(&self, func) => self.unwrap($panic: false) ?? func(self.error);

macro fault Result.unwrap_err(&self, bool $panic = true)
	=> self.err().get() ?? ($panic ??? abort("Result unwrapped a value when an error was expected.") : EXPECTED_ERROR?);
macro fault Result.unwrap_err_or(&self, fault _default) => self.safe_unwrap_err() ?? _default;

macro Result Result.and(self, Result alt) @operator(&) => self.is_err() ? self : alt;
macro Result Result.and_then(self, $typefrom($typeof(fn Result (fault f) => {})) func) => self.is_ok() ? func(self.value) : self;

macro Result Result.or(self, Result alt) @operator(|) => self.is_ok() ? self : alt;
macro Result Result.or_else(self, $typefrom($typeof(fn Result (fault f) => {})) func) => self.is_ok() ? self : func(self.error);

macro Result.map(&self, func)
{
	if (self.is_ok()) return result::ok(func(self.value));
	return result::err{$typefrom($typeof(func).returns)}(self.error);
}

<*
 @require $typeof(func).returns == $typeof(alt) : "The alternate value type and function return type must match."
*>
macro Result.map_or(&self, func, alt) => self.is_err() ? alt : func(self.value);

<*
 @require $typeof(func_ok).returns == $typeof(func_err).returns : "Both functions must return the same type."
*>
macro Result.map_or_else(&self, func_ok, func_err) => self.is_ok() ? func_ok(self.value) : func_err(self.error);
