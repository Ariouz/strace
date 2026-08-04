NAME := ft_strace
CC := cc
CFLAGS := -Wall -Wextra -Werror
CPPFLAGS := -Iincludes

SRCS := srcs/main.c srcs/tracer.c srcs/registers.c srcs/syscalls.c \
		srcs/format.c srcs/format_memory.c srcs/format_flags.c \
		srcs/path.c srcs/statistics.c
OBJS := $(SRCS:.c=.o)

.PHONY: all bonus clean fclean re

all: $(NAME)

bonus: CFLAGS += -DBONUS
bonus: fclean $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

%.o: %.c includes/ft_strace.h includes/registers.h includes/syscalls.h \
	includes/format.h includes/format_internal.h includes/path.h \
	includes/statistics.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

srcs/syscalls.o: includes/syscall_names_64.inc includes/syscall_names_32.inc \
	includes/syscall_nargs_64.inc includes/syscall_nargs_32.inc

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all
