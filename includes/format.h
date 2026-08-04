#ifndef FORMAT_H
# define FORMAT_H

# include "registers.h"

void	format_arguments(pid_t pid, t_abi abi, const char *name,
			const uint64_t args[6], unsigned int nargs, long long result);
void	format_return(const char *name, long long value);
const char	*format_signal_name(int signal_number);
int		format_syscall_deferred(const char *name);

#endif
