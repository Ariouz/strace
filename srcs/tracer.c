#define _GNU_SOURCE
#include "ft_strace.h"
#include "format.h"
#include "registers.h"
#include "statistics.h"
#include "syscalls.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

typedef struct s_trace
{
	pid_t			pid;
	int				started;
	int				entering_syscall;
	long long		current_syscall;
	t_abi			current_abi;
	uint64_t		arguments[6];
	int				deferred;
	int				summary;
	struct timespec	call_start;
	int				timer_started;
	t_statistics		statistics;
}	t_trace;

static void	print_error(const char *operation)
{
	fprintf(stderr, "ft_strace: %s: %s\n", operation, strerror(errno));
}

static void	child_main(int sync_pipe[2], const char *executable,
		char *const argv[])
{
	char	byte;
	ssize_t	read_result;

	close(sync_pipe[1]);
	do
		read_result = read(sync_pipe[0], &byte, 1);
	while (read_result == -1 && errno == EINTR);
	close(sync_pipe[0]);
	if (read_result != 1)
		_exit(1);
	execve(executable, argv, environ);
	fprintf(stderr, "ft_strace: %s: %s\n", argv[0], strerror(errno));
	_exit(127);
}

static void	start_call_timer(t_trace *trace)
{
	trace->timer_started = (clock_gettime(CLOCK_MONOTONIC,
			&trace->call_start) == 0);
}

static uint64_t	stop_call_timer(t_trace *trace)
{
	struct timespec	now;
	int64_t			seconds;
	int64_t			nanoseconds;

	if (!trace->timer_started || clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (0);
	trace->timer_started = 0;
	seconds = now.tv_sec - trace->call_start.tv_sec;
	nanoseconds = now.tv_nsec - trace->call_start.tv_nsec;
	if (nanoseconds < 0)
	{
		seconds--;
		nanoseconds += 1000000000;
	}
	if (seconds < 0)
		return (0);
	return ((uint64_t)seconds * 1000000000ULL + (uint64_t)nanoseconds);
}

static void	print_call(t_trace *trace, long long result)
{
	const char		*name;
	unsigned int	nargs;

	name = syscall_name(trace->current_abi, trace->current_syscall);
	if (name != NULL)
		fprintf(stderr, "%s(", name);
	else
		fprintf(stderr, "syscall_%lld(", trace->current_syscall);
	nargs = syscall_nargs(trace->current_abi, trace->current_syscall);
	format_arguments(trace->pid, trace->current_abi, name,
		trace->arguments, nargs, result);
}

static int	handle_syscall_stop(t_trace *trace)
{
	t_registers	registers;
	const char	*name;
	long long	result;
	uint64_t	nanoseconds;

	if (registers_read(trace->pid, &registers) == -1)
		return (-1);
	if (!trace->started)
	{
		if (registers.abi != ABI_X86_64
			|| registers_syscall(&registers) != SYS_execve
			|| registers_return(&registers) != -ENOSYS)
			return (0);
		trace->started = 1;
	}
	if (trace->entering_syscall)
	{
		trace->current_syscall = registers_syscall(&registers);
		trace->current_abi = registers.abi;
		registers_arguments(&registers, trace->arguments);
		name = syscall_name(trace->current_abi, trace->current_syscall);
		trace->deferred = format_syscall_deferred(name);
		if (!trace->summary && !trace->deferred)
			print_call(trace, -1);
		start_call_timer(trace);
		trace->entering_syscall = 0;
	}
	else
	{
		name = syscall_name(trace->current_abi, trace->current_syscall);
		result = registers_return(&registers);
		nanoseconds = stop_call_timer(trace);
		if (trace->summary)
			statistics_record(&trace->statistics, trace->current_abi,
				trace->current_syscall, result, nanoseconds);
		else
		{
			if (trace->deferred)
				print_call(trace, result);
			fprintf(stderr, ") = ");
			format_return(name, result);
			fputc('\n', stderr);
		}
		trace->entering_syscall = 1;
	}
	return (0);
}

static int	resume_tracee(pid_t pid, int signal_number)
{
	if (ptrace(PTRACE_SYSCALL, pid, NULL,
			(void *)(intptr_t)signal_number) == -1)
	{
		print_error("PTRACE_SYSCALL");
		return (-1);
	}
	return (0);
}

static int	handle_signal_stop(t_trace *trace, int status)
{
	siginfo_t	info;
	int			signal_number;

	signal_number = WSTOPSIG(status);
	if (((unsigned int)status >> 16) == PTRACE_EVENT_STOP
		&& (signal_number == SIGSTOP || signal_number == SIGTSTP
			|| signal_number == SIGTTIN || signal_number == SIGTTOU))
	{
		if (ptrace(PTRACE_LISTEN, trace->pid, NULL, NULL) == -1)
		{
			print_error("PTRACE_LISTEN");
			return (-1);
		}
		return (1);
	}
	errno = 0;
	if (ptrace(PTRACE_GETSIGINFO, trace->pid, NULL, &info) == -1)
	{
		if (errno == EINVAL && (signal_number == SIGSTOP
				|| signal_number == SIGTSTP || signal_number == SIGTTIN
				|| signal_number == SIGTTOU))
		{
			if (!trace->summary)
				fprintf(stderr, "--- stopped by %s ---\n",
					format_signal_name(signal_number));
			if (ptrace(PTRACE_LISTEN, trace->pid, NULL, NULL) == -1)
			{
				print_error("PTRACE_LISTEN");
				return (-1);
			}
			return (1);
		}
		print_error("PTRACE_GETSIGINFO");
		return (-1);
	}
	if (!trace->summary)
		fprintf(stderr, "--- %s {si_signo=%d, si_code=%d} ---\n",
			format_signal_name(info.si_signo), info.si_signo, info.si_code);
	if (signal_number == SIGTRAP && ((unsigned int)status >> 16) != 0)
		signal_number = 0;
	return (resume_tracee(trace->pid, signal_number));
}

static void	print_unfinished_syscall(t_trace *trace)
{
	if (!trace->started || trace->entering_syscall || trace->summary)
		return ;
	if (trace->deferred)
		print_call(trace, -1);
	fprintf(stderr, ") = ?\n");
}

static int	handle_tracee_end(t_trace *trace, int status)
{
	print_unfinished_syscall(trace);
	if (trace->summary)
		statistics_print(&trace->statistics);
	if (WIFEXITED(status))
	{
		if (!trace->summary)
			fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
		return (WEXITSTATUS(status));
	}
	if (!trace->summary)
		fprintf(stderr, "+++ killed by %s +++\n",
			format_signal_name(WTERMSIG(status)));
	return (128 + WTERMSIG(status));
}

static int	trace_loop(pid_t pid, int summary)
{
	t_trace	trace;
	int		status;
	int		result;

	trace.pid = pid;
	trace.started = 0;
	trace.entering_syscall = 1;
	trace.current_syscall = -1;
	trace.deferred = 0;
	trace.summary = summary;
	trace.timer_started = 0;
	statistics_init(&trace.statistics);
	if (resume_tracee(pid, 0) == -1)
		return (1);
	while (1)
	{
		if (waitpid(pid, &status, 0) == -1)
		{
			print_error("waitpid");
			return (1);
		}
		if (WIFEXITED(status) || WIFSIGNALED(status))
			return (handle_tracee_end(&trace, status));
		if (!WIFSTOPPED(status))
			continue ;
		if (WSTOPSIG(status) == (SIGTRAP | 0x80))
		{
			if (handle_syscall_stop(&trace) == -1
				|| resume_tracee(pid, 0) == -1)
				return (1);
		}
		else
		{
			result = handle_signal_stop(&trace, status);
			if (result == -1)
				return (1);
		}
	}
}

static int	wait_for_initial_stop(pid_t pid)
{
	int	status;

	if (waitpid(pid, &status, 0) == -1)
	{
		print_error("waitpid");
		return (-1);
	}
	if (!WIFSTOPPED(status))
	{
		fprintf(stderr, "ft_strace: tracee did not stop\n");
		errno = ECHILD;
		return (-1);
	}
	return (0);
}

static void	terminate_child(pid_t pid)
{
	int	wait_result;
	int	status;

	kill(pid, SIGKILL);
	wait_result = waitpid(pid, &status, 0);
	while (wait_result == -1 && errno == EINTR)
		wait_result = waitpid(pid, &status, 0);
}

static int	release_child(int fd)
{
	char	byte;
	ssize_t	write_result;

	byte = 1;
	do
		write_result = write(fd, &byte, 1);
	while (write_result == -1 && errno == EINTR);
	if (write_result != 1)
	{
		print_error("write");
		return (-1);
	}
	return (0);
}

int	trace_program(const char *executable, char *const argv[], int summary)
{
	unsigned long	options;
	pid_t			pid;
	int				result;
	int				sync_pipe[2];

	if (pipe(sync_pipe) == -1)
	{
		print_error("pipe");
		return (1);
	}
	pid = fork();
	if (pid == -1)
	{
		print_error("fork");
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		return (1);
	}
	if (pid == 0)
		child_main(sync_pipe, executable, argv);
	close(sync_pipe[0]);
	options = PTRACE_O_TRACESYSGOOD;
	if (ptrace(PTRACE_SEIZE, pid, NULL, (void *)(uintptr_t)options) == -1)
	{
		print_error("PTRACE_SEIZE");
		terminate_child(pid);
		close(sync_pipe[1]);
		return (1);
	}
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == -1)
	{
		print_error("PTRACE_INTERRUPT");
		terminate_child(pid);
		close(sync_pipe[1]);
		return (1);
	}
	if (wait_for_initial_stop(pid) == -1)
	{
		terminate_child(pid);
		close(sync_pipe[1]);
		return (1);
	}
	if (release_child(sync_pipe[1]) == -1)
	{
		terminate_child(pid);
		close(sync_pipe[1]);
		return (1);
	}
	close(sync_pipe[1]);
	result = trace_loop(pid, summary);
	return (result);
}
