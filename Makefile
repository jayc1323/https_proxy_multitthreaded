

CC = gcc
CFLAGS = -g -std=gnu99 -Wall -Wextra -Werror -Wfatal-errors $(INCLUDES) -pedantic
INCLUDES = -I/usr/include/openssl -I/usr/include/curl
LDFLAGS = -L/usr/lib/openssl -lssl -lcrypto -lpthread -lcurl


src = proxy_pthread.c proxy.c cJSON.c
obj = $(src:.c=.o)

all: proxy


proxy: $(obj)
	$(CC) $(obj) -o proxy $(CFLAGS) $(LDFLAGS)


%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@


.PHONY: clean
clean:
	rm -f $(obj) proxy
