#ifndef FORMAT_INTERNAL_H
# define FORMAT_INTERNAL_H

# include "registers.h"

# include <stddef.h>
# include <stdint.h>
# include <sys/types.h>

void	format_print_string(pid_t pid, uint64_t address, size_t limit);
void	format_print_buffer(pid_t pid, uint64_t address, size_t size);
void	format_print_argv(pid_t pid, t_abi abi, uint64_t address);

void	format_print_open_flags(uint64_t value);
void	format_print_fd_flags(uint64_t value);
void	format_print_protection(uint64_t value);
void	format_print_mmap_flags(uint64_t value);
void	format_print_access_mode(uint64_t value);

#endif
