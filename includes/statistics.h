#ifndef STATISTICS_H
# define STATISTICS_H

# include "registers.h"

# include <stddef.h>
# include <stdint.h>

# define STATISTICS_CAPACITY 1024

typedef struct s_stat_entry
{
	t_abi			abi;
	long long		number;
	uint64_t		calls;
	uint64_t		errors;
	uint64_t		nanoseconds;
}	t_stat_entry;

typedef struct s_statistics
{
	t_stat_entry	entries[STATISTICS_CAPACITY];
	size_t			size;
}	t_statistics;

void	statistics_init(t_statistics *statistics);
void	statistics_record(t_statistics *statistics, t_abi abi,
			long long number, long long result, uint64_t nanoseconds);
void	statistics_print(t_statistics *statistics);

#endif
