#include "syscalls.h"

#include <stddef.h>

static const char *const	g_syscalls_64[] = {
#include "syscall_names_64.inc"
};

static const char *const	g_syscalls_32[] = {
#include "syscall_names_32.inc"
};

/* Encoded as nargs + 1 so that an absent entry remains distinguishable. */
static const unsigned char	g_nargs_64[] = {
#include "syscall_nargs_64.inc"
};

static const unsigned char	g_nargs_32[] = {
#include "syscall_nargs_32.inc"
};

const char	*syscall_name(t_abi abi, long long number)
{
	if (number < 0)
		return (NULL);
	if (abi == ABI_I386)
	{
		if ((size_t)number >= sizeof(g_syscalls_32) / sizeof(g_syscalls_32[0]))
			return (NULL);
		return (g_syscalls_32[number]);
	}
	if ((size_t)number >= sizeof(g_syscalls_64) / sizeof(g_syscalls_64[0]))
		return (NULL);
	return (g_syscalls_64[number]);
}

unsigned int	syscall_nargs(t_abi abi, long long number)
{
	const unsigned char	*table;
	size_t				size;

	if (number < 0)
		return (6);
	if (abi == ABI_I386)
	{
		table = g_nargs_32;
		size = sizeof(g_nargs_32) / sizeof(g_nargs_32[0]);
	}
	else
	{
		table = g_nargs_64;
		size = sizeof(g_nargs_64) / sizeof(g_nargs_64[0]);
	}
	if ((size_t)number >= size || table[number] == 0)
		return (6);
	return (table[number] - 1);
}
