#include "path.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char	*make_candidate(const char *directory, size_t length,
		const char *command)
{
	char	*candidate;
	size_t	command_length;

	command_length = strlen(command);
	if (length == 0)
	{
		directory = ".";
		length = 1;
	}
	candidate = malloc(length + command_length + 2);
	if (candidate == NULL)
		return (NULL);
	memcpy(candidate, directory, length);
	candidate[length] = '/';
	memcpy(candidate + length + 1, command, command_length + 1);
	return (candidate);
}

char	*resolve_executable(const char *command)
{
	const char	*path;
	const char	*start;
	const char	*end;
	char		*candidate;
	struct stat	file_status;
	int			saw_permission_error;

	if (strchr(command, '/') != NULL)
		return (strdup(command));
	path = getenv("PATH");
	if (path == NULL)
		path = "/bin:/usr/bin";
	start = path;
	saw_permission_error = 0;
	while (1)
	{
		end = strchr(start, ':');
		if (end == NULL)
			end = start + strlen(start);
		candidate = make_candidate(start, (size_t)(end - start), command);
		if (candidate == NULL)
			return (NULL);
		if (access(candidate, X_OK) == 0)
		{
			if (stat(candidate, &file_status) == 0 && S_ISREG(file_status.st_mode))
				return (candidate);
			saw_permission_error = 1;
		}
		else if (errno == EACCES)
			saw_permission_error = 1;
		free(candidate);
		if (*end == '\0')
			break ;
		start = end + 1;
	}
	if (saw_permission_error)
		errno = EACCES;
	else
		errno = ENOENT;
	return (NULL);
}
