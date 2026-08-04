#include "statistics.h"
#include "syscalls.h"

#include <stdio.h>
#include <string.h>

void	statistics_init(t_statistics *statistics)
{
	memset(statistics, 0, sizeof(*statistics));
}

static t_stat_entry	*find_entry(t_statistics *statistics, t_abi abi,
		long long number)
{
	size_t	i;

	i = 0;
	while (i < statistics->size)
	{
		if (statistics->entries[i].abi == abi
			&& statistics->entries[i].number == number)
			return (&statistics->entries[i]);
		i++;
	}
	if (statistics->size == STATISTICS_CAPACITY)
		return (NULL);
	statistics->entries[statistics->size].abi = abi;
	statistics->entries[statistics->size].number = number;
	statistics->size++;
	return (&statistics->entries[statistics->size - 1]);
}

void	statistics_record(t_statistics *statistics, t_abi abi,
		long long number, long long result, uint64_t nanoseconds)
{
	t_stat_entry	*entry;

	entry = find_entry(statistics, abi, number);
	if (entry == NULL)
		return ;
	entry->calls++;
	if (result < 0 && result >= -4095)
		entry->errors++;
	entry->nanoseconds += nanoseconds;
}

static int	entry_goes_before(const t_stat_entry *left,
		const t_stat_entry *right)
{
	if (left->nanoseconds > right->nanoseconds)
		return (1);
	if (left->nanoseconds < right->nanoseconds)
		return (0);
	if (left->calls > right->calls)
		return (1);
	return (0);
}

static void	sort_entries(t_statistics *statistics)
{
	t_stat_entry	temporary;
	size_t			i;
	size_t			j;

	i = 0;
	while (i < statistics->size)
	{
		j = i + 1;
		while (j < statistics->size)
		{
			if (entry_goes_before(&statistics->entries[j],
					&statistics->entries[i]))
			{
				temporary = statistics->entries[i];
				statistics->entries[i] = statistics->entries[j];
				statistics->entries[j] = temporary;
			}
			j++;
		}
		i++;
	}
}

static void	print_entry(const t_stat_entry *entry, uint64_t total)
{
	const char	*name;
	double		percentage;
	double		seconds;
	uint64_t	microseconds_per_call;

	percentage = 0.0;
	if (total != 0)
		percentage = (double)entry->nanoseconds * 100.0 / (double)total;
	seconds = (double)entry->nanoseconds / 1000000000.0;
	microseconds_per_call = 0;
	if (entry->calls != 0)
		microseconds_per_call = entry->nanoseconds / entry->calls / 1000;
	name = syscall_name(entry->abi, entry->number);
	if (name == NULL)
	{
		fprintf(stderr, "%6.2f %11.6f %11llu %9llu %9llu syscall_%lld\n",
			percentage, seconds, (unsigned long long)microseconds_per_call,
			(unsigned long long)entry->calls, (unsigned long long)entry->errors,
			entry->number);
	}
	else
		fprintf(stderr, "%6.2f %11.6f %11llu %9llu %9llu %s\n",
			percentage, seconds, (unsigned long long)microseconds_per_call,
			(unsigned long long)entry->calls, (unsigned long long)entry->errors,
			name);
}

void	statistics_print(t_statistics *statistics)
{
	uint64_t	total_nanoseconds;
	uint64_t	total_calls;
	uint64_t	total_errors;
	size_t		i;

	sort_entries(statistics);
	total_nanoseconds = 0;
	total_calls = 0;
	total_errors = 0;
	i = 0;
	while (i < statistics->size)
	{
		total_nanoseconds += statistics->entries[i].nanoseconds;
		total_calls += statistics->entries[i].calls;
		total_errors += statistics->entries[i].errors;
		i++;
	}
	fprintf(stderr, "%% time     seconds  usecs/call     calls    errors syscall\n");
	fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
	i = 0;
	while (i < statistics->size)
	{
		print_entry(&statistics->entries[i], total_nanoseconds);
		i++;
	}
	fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
	fprintf(stderr, "100.00 %11.6f %11s %9llu %9llu total\n",
		(double)total_nanoseconds / 1000000000.0, "",
		(unsigned long long)total_calls, (unsigned long long)total_errors);
}
