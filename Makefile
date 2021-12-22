all: myping sniffer

myping: myping.c
	gcc -o myping myping.c

sniffer: sniffer.c
	gcc -o sniffer sniffer.c

clean:
	rm -f *.o sniffer myping

runm:
	 ./myping

runs:
	./sniffer

runs-strace:
	strace -f ./myping

runc-strace:
	strace -f ./sniffer