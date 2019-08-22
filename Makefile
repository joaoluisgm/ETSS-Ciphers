
#
# Makefile of ETSS Ciphers
#
#  Version 05/Fev/2018
#
#  Modification: 19/Mar/2018 	( All libs included )
#

CFLAGS += -Wall -g -O0 -fno-stack-protector -fPIC -pedantic-errors -std=c99

CC = gcc

open: aes128-O aes256-O gcm128-O gcm256-O 3des128-O 3des192-O aes128-Ot aes256-Ot gcm128-Ot gcm256-Ot 3des128-Ot 3des192-Ot 

boring: aes128-B aes256-B gcm128-B gcm256-B 3des128-B 3des192-B aes128-Bt aes256-Bt gcm128-Bt gcm256-Bt 3des128-Bt 3des192-Bt 

libre: aes128-L aes256-L gcm128-L gcm256-L 3des128-L 3des192-L aes128-Lt aes256-Lt gcm128-Lt gcm256-Lt 3des128-Lt 3des192-Lt 

mbed: aes128-M aes256-M gcm128-M gcm256-M 3des128-M 3des192-M aes128-Mt aes256-Mt gcm128-Mt gcm256-Mt 3des128-Mt 3des192-Mt 

wolf: aes128-W aes256-W 3des192-W aes128-Wt aes256-Wt 3des192-Wt

all: etss open boring libre mbed wolf


#
# -- BoringSSL --
#
aes128-B: aes128-B.o
	$(CC) $(CFLAGS) -o aes128-B etss.o aes128-B.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

aes128-Bt: aes128-Bt.o
	$(CC) $(CFLAGS) -o aes128-Bt etss.o aes128-Bt.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

aes256-B: aes256-B.o
	$(CC) $(CFLAGS) -o aes256-B etss.o aes256-B.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

aes256-Bt: aes256-Bt.o
	$(CC) $(CFLAGS) -o aes256-Bt etss.o aes256-Bt.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

3des128-B: 3des128-B.o
	$(CC) $(CFLAGS) -o 3des128-B etss.o 3des128-B.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

3des128-Bt: 3des128-Bt.o
	$(CC) $(CFLAGS) -o 3des128-Bt etss.o 3des128-Bt.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

3des192-B: 3des192-B.o
	$(CC) $(CFLAGS) -o 3des192-B etss.o 3des192-B.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

3des192-Bt: 3des192-Bt.o
	$(CC) $(CFLAGS) -o 3des192-Bt etss.o 3des192-Bt.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

gcm128-B: gcm128-B.o
	$(CC) $(CFLAGS) -o gcm128-B etss.o gcm128-B.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

gcm128-Bt: gcm128-Bt.o
	$(CC) $(CFLAGS) -o gcm128-Bt etss.o gcm128-Bt.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

gcm256-B: gcm256-B.o
	$(CC) $(CFLAGS) -o gcm256-B etss.o gcm256-B.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

gcm256-Bt: gcm256-Bt.o
	$(CC) $(CFLAGS) -o gcm256-Bt etss.o gcm256-Bt.o -I/opt/boringssl/include -L/opt/boringssl/lib -lcrypto

#
# -- LibreSSL --
#
aes128-L: aes128-L.o
	$(CC) $(CFLAGS) -o aes128-L etss.o aes128-L.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

aes128-Lt: aes128-Lt.o
	$(CC) $(CFLAGS) -o aes128-Lt etss.o aes128-Lt.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

aes256-L: aes256-L.o
	$(CC) $(CFLAGS) -o aes256-L etss.o aes256-L.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

aes256-Lt: aes256-Lt.o
	$(CC) $(CFLAGS) -o aes256-Lt etss.o aes256-Lt.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

3des128-L: 3des128-L.o
	$(CC) $(CFLAGS) -o 3des128-L etss.o 3des128-L.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

3des128-Lt: 3des128-Lt.o
	$(CC) $(CFLAGS) -o 3des128-Lt etss.o 3des128-Lt.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

3des192-L: 3des192-L.o
	$(CC) $(CFLAGS) -o 3des192-L etss.o 3des192-L.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

3des192-Lt: 3des192-Lt.o
	$(CC) $(CFLAGS) -o 3des192-Lt etss.o 3des192-Lt.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

gcm128-L: gcm128-L.o
	$(CC) $(CFLAGS) -o gcm128-L etss.o gcm128-L.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

gcm128-Lt: gcm128-Lt.o
	$(CC) $(CFLAGS) -o gcm128-Lt etss.o gcm128-Lt.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

gcm256-L: gcm256-L.o
	$(CC) $(CFLAGS) -o gcm256-L etss.o gcm256-L.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

gcm256-Lt: gcm256-Lt.o
	$(CC) $(CFLAGS) -o gcm256-Lt etss.o gcm256-Lt.o -I/opt/libressl/include -L/opt/libressl/lib -lcrypto

#
# -- MbedTLS --
#
aes128-M: aes128-M.o
	$(CC) $(CFLAGS) -o aes128-M etss.o aes128-M.o -lmbedcrypto

aes128-Mt: aes128-Mt.o
	$(CC) $(CFLAGS) -o aes128-Mt etss.o aes128-Mt.o -lmbedcrypto

aes256-M: aes256-M.o
	$(CC) $(CFLAGS) -o aes256-M etss.o aes256-M.o -lmbedcrypto

aes256-Mt: aes256-Mt.o
	$(CC) $(CFLAGS) -o aes256-Mt etss.o aes256-Mt.o -lmbedcrypto

3des128-M: 3des128-M.o
	$(CC) $(CFLAGS) -o 3des128-M etss.o 3des128-M.o -lmbedcrypto

3des128-Mt: 3des128-Mt.o
	$(CC) $(CFLAGS) -o 3des128-Mt etss.o 3des128-Mt.o -lmbedcrypto

3des192-M: 3des192-M.o
	$(CC) $(CFLAGS) -o 3des192-M etss.o 3des192-M.o -lmbedcrypto

3des192-Mt: 3des192-Mt.o
	$(CC) $(CFLAGS) -o 3des192-Mt etss.o 3des192-Mt.o -lmbedcrypto

gcm128-M: gcm128-M.o
	$(CC) $(CFLAGS) -o gcm128-M etss.o gcm128-M.o -lmbedcrypto

gcm128-Mt: gcm128-Mt.o
	$(CC) $(CFLAGS) -o gcm128-Mt etss.o gcm128-Mt.o -lmbedcrypto

gcm256-M: gcm256-M.o
	$(CC) $(CFLAGS) -o gcm256-M etss.o gcm256-M.o -lmbedcrypto

gcm256-Mt: gcm256-Mt.o
	$(CC) $(CFLAGS) -o gcm256-Mt etss.o gcm256-Mt.o -lmbedcrypto

#
# -- OpenSSL --
#
aes128-O: aes128-O.o
	$(CC) $(CFLAGS) -o aes128-O etss.o aes128-O.o -lcrypto
	#$(CC) $(CFLAGS) -o aes128-O etss.o aes128-O.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

aes128-Ot: aes128-Ot.o
	$(CC) $(CFLAGS) -o aes128-Ot etss.o aes128-Ot.o -lcrypto
	#$(CC) $(CFLAGS) -o aes128-Ot etss.o aes128-Ot.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

aes256-O: aes256-O.o
	$(CC) $(CFLAGS) -o aes256-O etss.o aes256-O.o -lcrypto
	#$(CC) $(CFLAGS) -o aes256-O etss.o aes256-O.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

aes256-Ot: aes256-Ot.o
	$(CC) $(CFLAGS) -o aes256-Ot etss.o aes256-Ot.o -lcrypto
	#$(CC) $(CFLAGS) -o aes256-Ot etss.o aes256-Ot.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

3des128-O: 3des128-O.o
	$(CC) $(CFLAGS) -o 3des128-O etss.o 3des128-O.o -lcrypto
	#$(CC) $(CFLAGS) -o 3des128-O etss.o 3des128-O.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

3des128-Ot: 3des128-Ot.o
	$(CC) $(CFLAGS) -o 3des128-Ot etss.o 3des128-Ot.o -lcrypto
	#$(CC) $(CFLAGS) -o 3des128-Ot etss.o 3des128-Ot.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

3des192-O: 3des192-O.o
	$(CC) $(CFLAGS) -o 3des192-O etss.o 3des192-O.o -lcrypto
	#$(CC) $(CFLAGS) -o 3des192-O etss.o 3des192-O.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

3des192-Ot: 3des192-Ot.o
	$(CC) $(CFLAGS) -o 3des192-Ot etss.o 3des192-Ot.o -lcrypto
	#$(CC) $(CFLAGS) -o 3des192-Ot etss.o 3des192-Ot.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

gcm128-O: gcm128-O.o
	$(CC) $(CFLAGS) -o gcm128-O etss.o gcm128-O.o -lcrypto
	#$(CC) $(CFLAGS) -o gcm128-O etss.o gcm128-O.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

gcm128-Ot: gcm128-Ot.o
	$(CC) $(CFLAGS) -o gcm128-Ot etss.o gcm128-Ot.o -lcrypto
	#$(CC) $(CFLAGS) -o gcm128-Ot etss.o gcm128-Ot.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

gcm256-O: gcm256-O.o
	$(CC) $(CFLAGS) -o gcm256-O etss.o gcm256-O.o -lcrypto
	#$(CC) $(CFLAGS) -o gcm256-O etss.o gcm256-O.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

gcm256-Ot: gcm256-Ot.o
	$(CC) $(CFLAGS) -o gcm256-Ot etss.o gcm256-Ot.o -lcrypto
	#$(CC) $(CFLAGS) -o gcm256-Ot etss.o gcm256-Ot.o -I/opt/openssl/include -L/opt/openssl/lib -L/lib/x86_64-linux-gnu -lcrypto -ldl

#
#
# -- WolfSSL --
#
aes128-W: aes128-W.o
	$(CC) $(CFLAGS) -o aes128-W etss.o aes128-W.o -I/usr/local/include/wolfssl -L/usr/local/lib -lwolfssl

aes128-Wt: aes128-Wt.o
	$(CC) $(CFLAGS) -o aes128-Wt etss.o aes128-Wt.o -I/usr/local/include/wolfssl -L/usr/local/lib -lwolfssl

aes256-W: aes256-W.o
	$(CC) $(CFLAGS) -o aes256-W etss.o aes256-W.o -I/usr/local/include/wolfssl -L/usr/local/lib -lwolfssl

aes256-Wt: aes256-Wt.o
	$(CC) $(CFLAGS) -o aes256-Wt etss.o aes256-Wt.o -I/usr/local/include/wolfssl -L/usr/local/lib -lwolfssl

3des192-W: 3des192-W.o
	$(CC) $(CFLAGS) -o 3des192-W etss.o 3des192-W.o -I/usr/local/include/wolfssl -L/usr/local/lib -lwolfssl

3des192-Wt: 3des192-Wt.o
	$(CC) $(CFLAGS) -o 3des192-Wt etss.o 3des192-Wt.o -I/usr/local/include/wolfssl -L/usr/local/lib -lwolfssl

#
#
# -- Support routines - ETSS --
#
etss: etss.o
	$(CC) $(CFLAGS) -c etss.c


# ------ Clean environment ------
#
clean:
	rm -rf *-B.o *-B *-L.o *-L *-M.o *-M *-O.o *-O *-W.o *-W *-Bt.o *-Bt *-Lt.o *-Lt *-Mt.o *-Mt *-Ot.o *-Ot *-Wt.o *-Wt
	TilClear

