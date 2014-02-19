all:
	gcc -fPIC -c pam_sge.c -Wall
	ld -x --shared -o pam_sge.so pam_sge.o
clean:
	rm *.o *.so
