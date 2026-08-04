#include "registers.h"

#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>

typedef struct s_regs32
{
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t eax;
	uint32_t xds;
	uint32_t xes;
	uint32_t xfs;
	uint32_t xgs;
	uint32_t orig_eax;
	uint32_t eip;
	uint32_t xcs;
	uint32_t eflags;
	uint32_t esp;
	uint32_t xss;
}	t_regs32;

int	registers_read(pid_t pid, t_registers *registers)
{
	struct iovec	iov;

	memset(registers, 0, sizeof(*registers));
	iov.iov_base = registers->data;
	iov.iov_len = sizeof(registers->data);
	if (ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS,
			&iov) == -1)
	{
		fprintf(stderr, "ft_strace: PTRACE_GETREGSET: %s\n", strerror(errno));
		return (-1);
	}
	registers->size = iov.iov_len;
	if (iov.iov_len == sizeof(struct user_regs_struct))
		registers->abi = ABI_X86_64;
	else if (iov.iov_len == sizeof(t_regs32))
		registers->abi = ABI_I386;
	else
	{
		fprintf(stderr, "ft_strace: unsupported register set size: %zu\n",
			iov.iov_len);
		return (-1);
	}
	return (0);
}

long long	registers_syscall(const t_registers *registers)
{
	if (registers->abi == ABI_I386)
		return (((const t_regs32 *)registers->data)->orig_eax);
	return (((const struct user_regs_struct *)registers->data)->orig_rax);
}

long long	registers_return(const t_registers *registers)
{
	if (registers->abi == ABI_I386)
		return ((int32_t)((const t_regs32 *)registers->data)->eax);
	return (((const struct user_regs_struct *)registers->data)->rax);
}

void	registers_arguments(const t_registers *registers, uint64_t args[6])
{
	const struct user_regs_struct	*regs64;
	const t_regs32					*regs32;

	if (registers->abi == ABI_I386)
	{
		regs32 = (const t_regs32 *)registers->data;
		args[0] = regs32->ebx;
		args[1] = regs32->ecx;
		args[2] = regs32->edx;
		args[3] = regs32->esi;
		args[4] = regs32->edi;
		args[5] = regs32->ebp;
		return ;
	}
	regs64 = (const struct user_regs_struct *)registers->data;
	args[0] = regs64->rdi;
	args[1] = regs64->rsi;
	args[2] = regs64->rdx;
	args[3] = regs64->r10;
	args[4] = regs64->r8;
	args[5] = regs64->r9;
}
