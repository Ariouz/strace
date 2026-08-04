#ifndef SYSCALLS_H
# define SYSCALLS_H

# include "registers.h"

const char	*syscall_name(t_abi abi, long long number);
unsigned int	syscall_nargs(t_abi abi, long long number);

#endif
