#define _GNU_SOURCE
#include "format_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>

#define STRING_LIMIT 256
#define BUFFER_LIMIT 64
#define ARGV_LIMIT 16

static ssize_t	read_tracee_memory(pid_t pid, uint64_t address,
		void *buffer, size_t size)
{
	struct iovec	local;
	struct iovec	remote;

	/* PTRACE_PEEKDATA is not allowed by the subject. */
	local.iov_base = buffer;
	local.iov_len = size;
	remote.iov_base = (void *)(uintptr_t)address;
	remote.iov_len = size;
	return (process_vm_readv(pid, &local, 1, &remote, 1, 0));
}

static void	print_escaped(const unsigned char *buffer, size_t size,
		int truncated)
{
	size_t	i;

	fputc('"', stderr);
	i = 0;
	while (i < size)
	{
		if (buffer[i] == '\n')
			fputs("\\n", stderr);
		else if (buffer[i] == '\r')
			fputs("\\r", stderr);
		else if (buffer[i] == '\t')
			fputs("\\t", stderr);
		else if (buffer[i] == '"' || buffer[i] == '\\')
			fprintf(stderr, "\\%c", buffer[i]);
		else if (buffer[i] >= 32 && buffer[i] < 127)
			fputc(buffer[i], stderr);
		else
			fprintf(stderr, "\\x%02x", buffer[i]);
		i++;
	}
	if (truncated)
		fputs("...", stderr);
	fputc('"', stderr);
}

void	format_print_string(pid_t pid, uint64_t address, size_t limit)
{
	unsigned char	buffer[STRING_LIMIT + 1];
	ssize_t			bytes_read;
	size_t			length;

	if (address == 0)
	{
		fputs("NULL", stderr);
		return ;
	}
	if (limit > STRING_LIMIT)
		limit = STRING_LIMIT;
	bytes_read = read_tracee_memory(pid, address, buffer, limit);
	if (bytes_read <= 0)
	{
		fprintf(stderr, "0x%llx", (unsigned long long)address);
		return ;
	}
	length = 0;
	while (length < (size_t)bytes_read && buffer[length] != '\0')
		length++;
	print_escaped(buffer, length,
		length == (size_t)bytes_read && length == limit);
}

void	format_print_buffer(pid_t pid, uint64_t address, size_t requested)
{
	unsigned char	buffer[BUFFER_LIMIT];
	size_t			read_size;
	ssize_t			bytes_read;

	if (address == 0)
	{
		fputs("NULL", stderr);
		return ;
	}
	read_size = requested;
	if (read_size > BUFFER_LIMIT)
		read_size = BUFFER_LIMIT;
	bytes_read = read_tracee_memory(pid, address, buffer, read_size);
	if (bytes_read < 0)
	{
		fprintf(stderr, "0x%llx", (unsigned long long)address);
		return ;
	}
	print_escaped(buffer, (size_t)bytes_read, requested > (size_t)bytes_read);
}

static int	read_pointer(pid_t pid, t_abi abi, uint64_t address,
		uint64_t *pointer)
{
	uint32_t	pointer32;
	ssize_t		bytes_read;

	*pointer = 0;
	if (abi == ABI_I386)
	{
		bytes_read = read_tracee_memory(pid, address, &pointer32,
				sizeof(pointer32));
		if (bytes_read != (ssize_t)sizeof(pointer32))
			return (-1);
		*pointer = pointer32;
		return (0);
	}
	bytes_read = read_tracee_memory(pid, address, pointer, sizeof(*pointer));
	if (bytes_read != (ssize_t)sizeof(*pointer))
		return (-1);
	return (0);
}

void	format_print_argv(pid_t pid, t_abi abi, uint64_t address)
{
	uint64_t	pointer;
	size_t		pointer_size;
	int			index;

	if (address == 0)
	{
		fputs("NULL", stderr);
		return ;
	}
	pointer_size = sizeof(uint64_t);
	if (abi == ABI_I386)
		pointer_size = sizeof(uint32_t);
	fputc('[', stderr);
	index = 0;
	while (index < ARGV_LIMIT)
	{
		if (read_pointer(pid, abi, address + index * pointer_size,
				&pointer) == -1 || pointer == 0)
			break ;
		if (index != 0)
			fputs(", ", stderr);
		format_print_string(pid, pointer, 128);
		index++;
	}
	if (index == ARGV_LIMIT)
		fputs(", ...", stderr);
	fputc(']', stderr);
}
