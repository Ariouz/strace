#include "ft_strace.h"
#include "path.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int	main(int argc, char **argv)
{
	int		summary;
	int		first_argument;
	int		result;
	char	*executable;

	summary = 0;
	first_argument = 1;
#ifdef BONUS
	if (argc > 1 && strcmp(argv[1], "-c") == 0)
	{
		summary = 1;
		first_argument++;
	}
#endif
	if (argc <= first_argument)
	{
#ifdef BONUS
		fprintf(stderr, "usage: %s [-c] program [arguments ...]\n", argv[0]);
#else
		fprintf(stderr, "usage: %s program [arguments ...]\n", argv[0]);
#endif
		return (1);
	}
#ifdef BONUS
	executable = resolve_executable(argv[first_argument]);
	if (executable == NULL)
	{
		if (errno == EACCES)
		{
			fprintf(stderr, "ft_strace: %s: Permission denied\n",
				argv[first_argument]);
			return (126);
		}
		if (errno == ENOMEM)
		{
			fprintf(stderr, "ft_strace: %s\n", strerror(errno));
			return (1);
		}
		fprintf(stderr, "ft_strace: %s: command not found\n",
			argv[first_argument]);
		return (127);
	}
#else
	executable = argv[first_argument];
#endif
	result = trace_program(executable, &argv[first_argument], summary);
#ifdef BONUS
	free(executable);
#endif
	return (result);
}
