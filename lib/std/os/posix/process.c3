module std::os::posix @if(env::POSIX);
import libc;

struct Posix_spawn_file_actions_t
{
	int __allocated;
	int __used;
	void* __actions;
	int[16] __pad;
}

struct Posix_spawnattr_t
{
	void*[42] opaque;
}

extern fn CInt posix_spawn_file_actions_init(Posix_spawn_file_actions_t *file_actions);
extern fn CInt posix_spawn_file_actions_destroy(Posix_spawn_file_actions_t *file_actions);
extern fn CInt posix_spawn_file_actions_addclose(Posix_spawn_file_actions_t *file_actions, CInt fd);
extern fn CInt posix_spawn_file_actions_adddup2(Posix_spawn_file_actions_t *file_actions, CInt fd, CInt newfd);

extern fn CInt get_nprocs();
extern fn CInt get_nprocs_conf();

alias spawn_file_actions_init = posix_spawn_file_actions_init;
alias spawn_file_actions_destroy = posix_spawn_file_actions_destroy;
alias spawn_file_actions_addclose = posix_spawn_file_actions_addclose;
alias spawn_file_actions_adddup2 = posix_spawn_file_actions_adddup2;

extern fn CInt posix_spawnp(Pid_t* pid, char* file, Posix_spawn_file_actions_t* file_actions,
	Posix_spawnattr_t* attrp, ZString* argv, ZString* envp);
extern fn CInt posix_spawn(Pid_t* pid, char* file, Posix_spawn_file_actions_t* file_actions,
	Posix_spawnattr_t* attrp, ZString* argv, ZString* envp);
alias spawnp = posix_spawnp;
alias spawn = posix_spawn;

extern fn CInt getpid();
extern fn CInt kill(Pid_t pid, CInt sig);
extern fn Pid_t waitpid(Pid_t pid, CInt* stat_loc, int options);
extern fn CInt raise(CInt sig);
extern fn ZString* backtrace_symbols(void** buffer, CInt size);
extern fn void backtrace_symbols_fd(void** buffer, CInt size, CInt fd);
macro CInt wEXITSTATUS(CInt status) => (status & 0xff00) >> 8;
macro CInt wTERMSIG(CInt status) => status & 0x7f;
macro CInt wSTOPSIG(CInt status) => wEXITSTATUS(status);
macro bool wIFEXITED(CInt status) => wTERMSIG(status) == 0;
macro bool wIFSIGNALED(CInt status) => ((ichar) ((status & 0x7f) + 1) >> 1) > 0;
macro bool wIFSTOPPED(CInt status) => (status & 0xff) == 0x7f;
macro bool wIFCONTINUED(CInt status) => status == __W_CONTINUED;
macro CInt wWCOREDUMP(CInt status) => status & __WCOREFLAG;
macro CInt w_EXITCODE(CInt ret, CInt sig) => (ret << 8) | sig;
macro CInt w_STOPCODE(CInt sig) => (sig << 8) | 0x7f;
const CInt __WCOREFLAG = 0x80;
const CInt __W_CONTINUED = 0xffff;
const CInt WNOHANG = 1;
const CInt WUNTRACES = 2;

JmpBuf backtrace_jmpbuf @local;
alias BacktraceFn = fn CInt(void** buffer, CInt size);

extern fn CInt backtrace(void** buffer, CInt size) @if(env::OPENBSD);

fn CInt backtrace(void** buffer, CInt size) @if(!env::OPENBSD)
{
	if (size < 1) return 0;
	void* handle = libc::dlopen("libc.so.6", libc::RTLD_LAZY|libc::RTLD_NODELETE);
	if (handle)
	{
		BacktraceFn backtrace_fn = libc::dlsym(handle, "backtrace");
		libc::dlclose(handle);
		if (backtrace_fn)
		{
			return backtrace_fn(buffer, size);
		}
	}
	// Loop through the return addresses until we hit a signal.
	// This avoids using the frame address.
	SignalFunction restore_backtrace = fn void(CInt) {
		libc::longjmp(&backtrace_jmpbuf, 1);
	};
	SignalFunction sig_bus = libc::signal(libc::SIGBUS, restore_backtrace);
	SignalFunction sig_segv = libc::signal(libc::SIGSEGV, restore_backtrace);
	SignalFunction sig_ill = libc::signal(libc::SIGILL, restore_backtrace);

	void*[128] buffer_first;
	int i = 0;
	for (i = 0; i < size; i++)
	{
		if (libc::setjmp(&backtrace_jmpbuf) == 1) break;
		buffer[i] = builtin::get_returnaddress(i);
		if (!buffer[i]) break;
	}
	libc::signal(libc::SIGBUS, sig_bus);
	libc::signal(libc::SIGSEGV, sig_segv);
	libc::signal(libc::SIGILL, sig_ill);
	return i;
}
