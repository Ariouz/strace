#include "format.h"
#include "format_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef enum e_arg_kind
{
	A_HEX, A_DEC, A_UINT, A_FD, A_SIZE, A_PTR, A_STR, A_BUF, A_ARGV,
	A_MODE, A_OPEN, A_FD_FLAGS, A_PROT, A_MMAP, A_ATFD, A_SIGNAL,
	A_WHENCE, A_ACCESS, A_OUTBUF
}	t_arg_kind;

typedef struct s_spec
{
	const char	*name;
	t_arg_kind	args[6];
}	t_spec;

typedef struct s_named_value
{
	int			value;
	const char	*name;
}	t_named_value;

#define S(name, a, b, c, d, e, f) {name, {a, b, c, d, e, f}}

static const t_spec	g_specs[] = {
	S("execve", A_STR, A_ARGV, A_PTR, A_HEX, A_HEX, A_HEX),
	S("execveat", A_ATFD, A_STR, A_ARGV, A_PTR, A_HEX, A_HEX),
	S("read", A_FD, A_OUTBUF, A_SIZE, A_HEX, A_HEX, A_HEX),
	S("write", A_FD, A_BUF, A_SIZE, A_HEX, A_HEX, A_HEX),
	S("pread64", A_FD, A_OUTBUF, A_SIZE, A_DEC, A_HEX, A_HEX),
	S("pwrite64", A_FD, A_BUF, A_SIZE, A_DEC, A_HEX, A_HEX),
	S("readv", A_FD, A_PTR, A_DEC, A_HEX, A_HEX, A_HEX),
	S("writev", A_FD, A_PTR, A_DEC, A_HEX, A_HEX, A_HEX),
	S("open", A_STR, A_OPEN, A_MODE, A_HEX, A_HEX, A_HEX),
	S("openat", A_ATFD, A_STR, A_OPEN, A_MODE, A_HEX, A_HEX),
	S("openat2", A_ATFD, A_STR, A_PTR, A_SIZE, A_HEX, A_HEX),
	S("close", A_FD, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("access", A_STR, A_ACCESS, A_HEX, A_HEX, A_HEX, A_HEX),
	S("faccessat", A_ATFD, A_STR, A_ACCESS, A_HEX, A_HEX, A_HEX),
	S("faccessat2", A_ATFD, A_STR, A_ACCESS, A_HEX, A_HEX, A_HEX),
	S("stat", A_STR, A_PTR, A_HEX, A_HEX, A_HEX, A_HEX),
	S("lstat", A_STR, A_PTR, A_HEX, A_HEX, A_HEX, A_HEX),
	S("fstat", A_FD, A_PTR, A_HEX, A_HEX, A_HEX, A_HEX),
	S("newfstatat", A_ATFD, A_STR, A_PTR, A_HEX, A_HEX, A_HEX),
	S("mmap", A_PTR, A_SIZE, A_PROT, A_MMAP, A_FD, A_HEX),
	S("mmap2", A_PTR, A_SIZE, A_PROT, A_MMAP, A_FD, A_HEX),
	S("mprotect", A_PTR, A_SIZE, A_PROT, A_HEX, A_HEX, A_HEX),
	S("munmap", A_PTR, A_SIZE, A_HEX, A_HEX, A_HEX, A_HEX),
	S("mremap", A_PTR, A_SIZE, A_SIZE, A_HEX, A_PTR, A_HEX),
	S("brk", A_PTR, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("ioctl", A_FD, A_HEX, A_PTR, A_HEX, A_HEX, A_HEX),
	S("lseek", A_FD, A_DEC, A_WHENCE, A_HEX, A_HEX, A_HEX),
	S("arch_prctl", A_HEX, A_PTR, A_HEX, A_HEX, A_HEX, A_HEX),
	S("set_tid_address", A_PTR, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("set_robust_list", A_PTR, A_SIZE, A_HEX, A_HEX, A_HEX, A_HEX),
	S("rseq", A_PTR, A_SIZE, A_HEX, A_HEX, A_HEX, A_HEX),
	S("exit", A_DEC, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("exit_group", A_DEC, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("kill", A_DEC, A_SIGNAL, A_HEX, A_HEX, A_HEX, A_HEX),
	S("tkill", A_DEC, A_SIGNAL, A_HEX, A_HEX, A_HEX, A_HEX),
	S("tgkill", A_DEC, A_DEC, A_SIGNAL, A_HEX, A_HEX, A_HEX),
	S("rt_sigaction", A_SIGNAL, A_PTR, A_PTR, A_SIZE, A_HEX, A_HEX),
	S("rt_sigprocmask", A_DEC, A_PTR, A_PTR, A_SIZE, A_HEX, A_HEX),
	S("fcntl", A_FD, A_DEC, A_HEX, A_HEX, A_HEX, A_HEX),
	S("dup", A_FD, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("dup2", A_FD, A_FD, A_HEX, A_HEX, A_HEX, A_HEX),
	S("dup3", A_FD, A_FD, A_FD_FLAGS, A_HEX, A_HEX, A_HEX),
	S("pipe", A_PTR, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("pipe2", A_PTR, A_FD_FLAGS, A_HEX, A_HEX, A_HEX, A_HEX),
	S("clone", A_HEX, A_PTR, A_PTR, A_PTR, A_PTR, A_HEX),
	S("clone3", A_PTR, A_SIZE, A_HEX, A_HEX, A_HEX, A_HEX),
	S("wait4", A_DEC, A_PTR, A_HEX, A_PTR, A_HEX, A_HEX),
	S("nanosleep", A_PTR, A_PTR, A_HEX, A_HEX, A_HEX, A_HEX),
	S("clock_nanosleep", A_DEC, A_HEX, A_PTR, A_PTR, A_HEX, A_HEX),
	S("clock_gettime", A_DEC, A_PTR, A_HEX, A_HEX, A_HEX, A_HEX),
	S("getrandom", A_OUTBUF, A_SIZE, A_HEX, A_HEX, A_HEX, A_HEX),
	S("futex", A_PTR, A_DEC, A_DEC, A_PTR, A_PTR, A_DEC),
	S("prlimit64", A_DEC, A_DEC, A_PTR, A_PTR, A_HEX, A_HEX),
	S("uname", A_PTR, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("getcwd", A_OUTBUF, A_SIZE, A_HEX, A_HEX, A_HEX, A_HEX),
	S("chdir", A_STR, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("unlink", A_STR, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("unlinkat", A_ATFD, A_STR, A_HEX, A_HEX, A_HEX, A_HEX),
	S("mkdir", A_STR, A_MODE, A_HEX, A_HEX, A_HEX, A_HEX),
	S("mkdirat", A_ATFD, A_STR, A_MODE, A_HEX, A_HEX, A_HEX),
	S("rmdir", A_STR, A_HEX, A_HEX, A_HEX, A_HEX, A_HEX),
	S("chmod", A_STR, A_MODE, A_HEX, A_HEX, A_HEX, A_HEX),
	S("fchmod", A_FD, A_MODE, A_HEX, A_HEX, A_HEX, A_HEX),
	S("rename", A_STR, A_STR, A_HEX, A_HEX, A_HEX, A_HEX),
	S("renameat", A_ATFD, A_STR, A_ATFD, A_STR, A_HEX, A_HEX),
	S("renameat2", A_ATFD, A_STR, A_ATFD, A_STR, A_HEX, A_HEX),
	S("readlink", A_STR, A_OUTBUF, A_SIZE, A_HEX, A_HEX, A_HEX),
	S("readlinkat", A_ATFD, A_STR, A_OUTBUF, A_SIZE, A_HEX, A_HEX),
	S("socket", A_DEC, A_DEC, A_DEC, A_HEX, A_HEX, A_HEX),
	S("connect", A_FD, A_PTR, A_SIZE, A_HEX, A_HEX, A_HEX),
	S("bind", A_FD, A_PTR, A_SIZE, A_HEX, A_HEX, A_HEX),
	S("listen", A_FD, A_DEC, A_HEX, A_HEX, A_HEX, A_HEX),
	S("shutdown", A_FD, A_DEC, A_HEX, A_HEX, A_HEX, A_HEX),
	S("sendto", A_FD, A_BUF, A_SIZE, A_HEX, A_PTR, A_SIZE),
	S("recvfrom", A_FD, A_PTR, A_SIZE, A_HEX, A_PTR, A_PTR),
};

static const t_spec	*find_spec(const char *name)
{
	size_t	i;

	if (name == NULL)
		return (NULL);
	i = 0;
	while (i < sizeof(g_specs) / sizeof(g_specs[0]))
	{
		if (strcmp(g_specs[i].name, name) == 0)
			return (&g_specs[i]);
		i++;
	}
	return (NULL);
}

static void	print_argument(pid_t pid, t_abi abi, t_arg_kind kind,
		uint64_t value, uint64_t next, long long result)
{
	if (kind == A_DEC)
		fprintf(stderr, "%lld", (long long)value);
	else if (kind == A_UINT || kind == A_SIZE)
		fprintf(stderr, "%llu", (unsigned long long)value);
	else if (kind == A_FD)
		fprintf(stderr, "%d", (int)value);
	else if (kind == A_PTR)
	{
		if (value == 0)
			fputs("NULL", stderr);
		else
			fprintf(stderr, "0x%llx", (unsigned long long)value);
	}
	else if (kind == A_STR)
		format_print_string(pid, value, 256);
	else if (kind == A_BUF)
		format_print_buffer(pid, value, (size_t)next);
	else if (kind == A_OUTBUF && result >= 0)
		format_print_buffer(pid, value, (size_t)result);
	else if (kind == A_OUTBUF)
		fprintf(stderr, "0x%llx", (unsigned long long)value);
	else if (kind == A_ARGV)
		format_print_argv(pid, abi, value);
	else if (kind == A_MODE)
		fprintf(stderr, "0%llo", (unsigned long long)value);
	else if (kind == A_OPEN)
		format_print_open_flags(value);
	else if (kind == A_FD_FLAGS)
		format_print_fd_flags(value);
	else if (kind == A_PROT)
		format_print_protection(value);
	else if (kind == A_MMAP)
		format_print_mmap_flags(value);
	else if (kind == A_ATFD && (int32_t)value == AT_FDCWD)
		fputs("AT_FDCWD", stderr);
	else if (kind == A_ATFD)
		fprintf(stderr, "%d", (int)value);
	else if (kind == A_SIGNAL)
		fputs(format_signal_name((int)value), stderr);
	else if (kind == A_WHENCE && value == SEEK_SET)
		fputs("SEEK_SET", stderr);
	else if (kind == A_WHENCE && value == SEEK_CUR)
		fputs("SEEK_CUR", stderr);
	else if (kind == A_WHENCE && value == SEEK_END)
		fputs("SEEK_END", stderr);
	else if (kind == A_ACCESS)
		format_print_access_mode(value);
	else
		fprintf(stderr, "0x%llx", (unsigned long long)value);
}

void	format_arguments(pid_t pid, t_abi abi, const char *name,
		const uint64_t args[6], unsigned int nargs, long long result)
{
	const t_spec	*spec;
	uint64_t		next_argument;
	unsigned int	i;

	spec = find_spec(name);
	if (name != NULL && strcmp(name, "open") == 0
		&& !(args[1] & O_CREAT)
#ifdef O_TMPFILE
		&& (args[1] & O_TMPFILE) != O_TMPFILE
#endif
		)
		nargs = 2;
	if (name != NULL && strcmp(name, "openat") == 0
		&& !(args[2] & O_CREAT)
#ifdef O_TMPFILE
		&& (args[2] & O_TMPFILE) != O_TMPFILE
#endif
		)
		nargs = 3;
	i = 0;
	while (i < nargs)
	{
		if (i != 0)
			fputs(", ", stderr);
		next_argument = 0;
		if (i < 5)
			next_argument = args[i + 1];
		if (spec == NULL)
			print_argument(pid, abi, A_HEX, args[i], next_argument, result);
		else
			print_argument(pid, abi, spec->args[i], args[i],
				next_argument, result);
		i++;
	}
}

int	format_syscall_deferred(const char *name)
{
	return (name != NULL && (strcmp(name, "read") == 0
			|| strcmp(name, "pread64") == 0 || strcmp(name, "getrandom") == 0
			|| strcmp(name, "getcwd") == 0 || strcmp(name, "readlink") == 0
			|| strcmp(name, "readlinkat") == 0));
}

static int	pointer_return(const char *name)
{
	return (name != NULL && (strcmp(name, "mmap") == 0
			|| strcmp(name, "mmap2") == 0 || strcmp(name, "mremap") == 0
			|| strcmp(name, "brk") == 0 || strcmp(name, "shmat") == 0));
}

static const char	*find_value_name(const t_named_value *values,
		size_t count, int value)
{
	size_t	i;

	i = 0;
	while (i < count)
	{
		if (values[i].value == value)
			return (values[i].name);
		i++;
	}
	return (NULL);
}

static const char	*error_name(int error_number)
{
	static const t_named_value	errors[] = {
		{EPERM, "EPERM"}, {ENOENT, "ENOENT"}, {ESRCH, "ESRCH"},
		{EINTR, "EINTR"}, {EIO, "EIO"}, {ENXIO, "ENXIO"},
		{E2BIG, "E2BIG"}, {ENOEXEC, "ENOEXEC"}, {EBADF, "EBADF"},
		{ECHILD, "ECHILD"}, {EAGAIN, "EAGAIN"}, {ENOMEM, "ENOMEM"},
		{EACCES, "EACCES"}, {EFAULT, "EFAULT"}, {EBUSY, "EBUSY"},
		{EEXIST, "EEXIST"}, {EXDEV, "EXDEV"}, {ENODEV, "ENODEV"},
		{ENOTDIR, "ENOTDIR"}, {EISDIR, "EISDIR"}, {EINVAL, "EINVAL"},
		{ENFILE, "ENFILE"}, {EMFILE, "EMFILE"}, {ENOTTY, "ENOTTY"},
		{EFBIG, "EFBIG"}, {ENOSPC, "ENOSPC"}, {ESPIPE, "ESPIPE"},
		{EROFS, "EROFS"}, {EMLINK, "EMLINK"}, {EPIPE, "EPIPE"},
		{EDOM, "EDOM"}, {ERANGE, "ERANGE"}, {EDEADLK, "EDEADLK"},
		{ENAMETOOLONG, "ENAMETOOLONG"}, {ENOLCK, "ENOLCK"},
		{ENOSYS, "ENOSYS"}, {ENOTEMPTY, "ENOTEMPTY"}, {ELOOP, "ELOOP"},
		{ENOMSG, "ENOMSG"}, {EIDRM, "EIDRM"}, {ETIMEDOUT, "ETIMEDOUT"},
		{ECONNREFUSED, "ECONNREFUSED"}, {ECONNRESET, "ECONNRESET"},
		{ENOTCONN, "ENOTCONN"}, {EADDRINUSE, "EADDRINUSE"},
		{EADDRNOTAVAIL, "EADDRNOTAVAIL"}, {ENETUNREACH, "ENETUNREACH"},
		{EOPNOTSUPP, "EOPNOTSUPP"},
	};

	return (find_value_name(errors, sizeof(errors) / sizeof(errors[0]),
			error_number));
}

void	format_return(const char *name, long long value)
{
	int	error_number;
	const char	*name_of_error;

	if (value < 0 && value >= -4095)
	{
		error_number = (int)-value;
		name_of_error = error_name(error_number);
		if (name_of_error != NULL)
			fprintf(stderr, "-1 %s (%s)", name_of_error,
				strerror(error_number));
		else
			fprintf(stderr, "-1 ERRNO_%d (%s)", error_number,
				strerror(error_number));
	}
	else if (pointer_return(name))
		fprintf(stderr, "0x%llx", (unsigned long long)value);
	else
		fprintf(stderr, "%lld", value);
}

const char	*format_signal_name(int signal_number)
{
	static const t_named_value	signals[] = {
		{SIGHUP, "SIGHUP"}, {SIGINT, "SIGINT"}, {SIGQUIT, "SIGQUIT"},
		{SIGILL, "SIGILL"}, {SIGABRT, "SIGABRT"}, {SIGFPE, "SIGFPE"},
		{SIGKILL, "SIGKILL"}, {SIGSEGV, "SIGSEGV"}, {SIGPIPE, "SIGPIPE"},
		{SIGALRM, "SIGALRM"}, {SIGTERM, "SIGTERM"}, {SIGUSR1, "SIGUSR1"},
		{SIGUSR2, "SIGUSR2"}, {SIGCHLD, "SIGCHLD"}, {SIGCONT, "SIGCONT"},
		{SIGSTOP, "SIGSTOP"}, {SIGTSTP, "SIGTSTP"}, {SIGTTIN, "SIGTTIN"},
		{SIGTTOU, "SIGTTOU"}, {SIGBUS, "SIGBUS"}, {SIGPROF, "SIGPROF"},
		{SIGSYS, "SIGSYS"}, {SIGTRAP, "SIGTRAP"}, {SIGURG, "SIGURG"},
		{SIGVTALRM, "SIGVTALRM"}, {SIGXCPU, "SIGXCPU"},
		{SIGXFSZ, "SIGXFSZ"}, {SIGWINCH, "SIGWINCH"},
	};
	const char	*name;

	name = find_value_name(signals, sizeof(signals) / sizeof(signals[0]),
			signal_number);
	if (name != NULL)
		return (name);
	return ("SIGUNKNOWN");
}
