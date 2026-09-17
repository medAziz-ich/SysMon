CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LIBS = -lcurl -lpthread -lsqlite3

all: sysmon-agent

sysmon-agent: main.o cJSON.o queue.o
	$(CC) $^ -o $@ $(LIBS)

main.o: main.c cJSON.h queue.h
	$(CC) $(CFLAGS) -c main.c

cJSON.o: cJSON.c cJSON.h
	$(CC) $(CFLAGS) -c cJSON.c

queue.o: queue.c queue.h
	$(CC) $(CFLAGS) -c queue.c

install: sysmon-agent
	# FIX #2 — create dedicated low-privilege system user
	useradd --system --no-create-home --shell /usr/sbin/nologin sysmon 2>/dev/null || true
	install -m 755 sysmon-agent /usr/local/bin/sysmon-agent
	install -d /etc/sysmon-agent
	install -d /var/lib/sysmon-agent
	install -m 600 config.json /etc/sysmon-agent/config.json
	# Copy server cert for SSL verification (FIX #3)
	@if [ -f server.crt ]; then \
		install -m 644 server.crt /etc/sysmon-agent/server.crt; \
		echo "✔ server.crt installed for SSL verification"; \
	else \
		echo "WARNING: server.crt not found — copy it to /etc/sysmon-agent/server.crt manually"; \
	fi
	chown -R sysmon:sysmon /etc/sysmon-agent /var/lib/sysmon-agent
	chmod 750 /etc/sysmon-agent /var/lib/sysmon-agent
	install -m 644 sysmon-agent.service /etc/systemd/system/sysmon-agent.service
	systemctl daemon-reload

clean:
	rm -f *.o sysmon-agent
