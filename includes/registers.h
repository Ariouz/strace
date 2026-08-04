#ifndef REGISTERS_H
# define REGISTERS_H

# include <stddef.h>
# include <stdint.h>
# include <sys/types.h>

typedef enum e_abi
{
	ABI_X86_64,
	ABI_I386
}	t_abi;

typedef struct s_registers
{
	unsigned char	data[256];
	size_t			size;
	t_abi			abi;
}	t_registers;

int			registers_read(pid_t pid, t_registers *registers);
long long	registers_syscall(const t_registers *registers);
long long	registers_return(const t_registers *registers);
void		registers_arguments(const t_registers *registers, uint64_t args[6]);

#endif
