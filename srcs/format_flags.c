#include "format_internal.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct s_flag_name
{
	uint64_t	value;
	const char	*name;
}	t_flag_name;

static void	print_separator(int *printed)
{
	if (*printed)
		fputc('|', stderr);
	*printed = 1;
}

static void	print_flags(uint64_t *value, const t_flag_name *flags,
		size_t count, int *printed)
{
	size_t	i;

	i = 0;
	while (i < count)
	{
		if (flags[i].value != 0
			&& (*value & flags[i].value) == flags[i].value)
		{
			print_separator(printed);
			fputs(flags[i].name, stderr);
			*value &= ~flags[i].value;
		}
		i++;
	}
}

void	format_print_open_flags(uint64_t value)
{
	static const t_flag_name	flags[] = {
		{O_CREAT, "O_CREAT"}, {O_EXCL, "O_EXCL"},
		{O_TRUNC, "O_TRUNC"}, {O_APPEND, "O_APPEND"},
		{O_NONBLOCK, "O_NONBLOCK"}, {O_DIRECTORY, "O_DIRECTORY"},
		{O_NOFOLLOW, "O_NOFOLLOW"}, {O_CLOEXEC, "O_CLOEXEC"},
#ifdef O_PATH
		{O_PATH, "O_PATH"},
#endif
	};
	int	printed;

	printed = 1;
	if ((value & O_ACCMODE) == O_WRONLY)
		fputs("O_WRONLY", stderr);
	else if ((value & O_ACCMODE) == O_RDWR)
		fputs("O_RDWR", stderr);
	else
		fputs("O_RDONLY", stderr);
	value &= ~((uint64_t)O_ACCMODE);
	print_flags(&value, flags, sizeof(flags) / sizeof(flags[0]), &printed);
	if (value != 0)
		fprintf(stderr, "|0x%llx", (unsigned long long)value);
}

void	format_print_fd_flags(uint64_t value)
{
	static const t_flag_name	flags[] = {
		{O_CLOEXEC, "O_CLOEXEC"}, {O_NONBLOCK, "O_NONBLOCK"},
	};
	int	printed;

	if (value == 0)
	{
		fputc('0', stderr);
		return ;
	}
	printed = 0;
	print_flags(&value, flags, sizeof(flags) / sizeof(flags[0]), &printed);
	if (value != 0)
	{
		print_separator(&printed);
		fprintf(stderr, "0x%llx", (unsigned long long)value);
	}
}

void	format_print_protection(uint64_t value)
{
	static const t_flag_name	flags[] = {
		{PROT_READ, "PROT_READ"}, {PROT_WRITE, "PROT_WRITE"},
		{PROT_EXEC, "PROT_EXEC"},
	};
	int	printed;

	if (value == PROT_NONE)
	{
		fputs("PROT_NONE", stderr);
		return ;
	}
	printed = 0;
	print_flags(&value, flags, sizeof(flags) / sizeof(flags[0]), &printed);
	if (value != 0)
	{
		print_separator(&printed);
		fprintf(stderr, "0x%llx", (unsigned long long)value);
	}
}

void	format_print_mmap_flags(uint64_t value)
{
	static const t_flag_name	flags[] = {
		{MAP_SHARED, "MAP_SHARED"}, {MAP_PRIVATE, "MAP_PRIVATE"},
		{MAP_FIXED, "MAP_FIXED"}, {MAP_ANONYMOUS, "MAP_ANONYMOUS"},
#ifdef MAP_DENYWRITE
		{MAP_DENYWRITE, "MAP_DENYWRITE"},
#endif
#ifdef MAP_STACK
		{MAP_STACK, "MAP_STACK"},
#endif
	};
	int	printed;

	printed = 0;
	print_flags(&value, flags, sizeof(flags) / sizeof(flags[0]), &printed);
	if (value != 0 || !printed)
	{
		print_separator(&printed);
		fprintf(stderr, "0x%llx", (unsigned long long)value);
	}
}

void	format_print_access_mode(uint64_t value)
{
	static const t_flag_name	flags[] = {
		{R_OK, "R_OK"}, {W_OK, "W_OK"}, {X_OK, "X_OK"},
	};
	int	printed;

	if (value == F_OK)
	{
		fputs("F_OK", stderr);
		return ;
	}
	printed = 0;
	print_flags(&value, flags, sizeof(flags) / sizeof(flags[0]), &printed);
	if (value != 0)
	{
		print_separator(&printed);
		fprintf(stderr, "0x%llx", (unsigned long long)value);
	}
}
