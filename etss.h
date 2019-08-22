
#ifndef ETSS_H_
#define ETSS_H_
 
//#include <stdio.h>

//#define IP_SIZE 1024
//#define OP_SIZE 1032

typedef struct st_key128 { 
	unsigned char data[16];
	int size;
} key128;

typedef struct st_key192 { 
	unsigned char data[24];
	int size;
} key192;

typedef struct st_key256 { 
	unsigned char data[32];
	int size;
} key256;

typedef struct st_iv8 { 
	unsigned char data[8];
	int size;
} iv8;

typedef struct st_iv16 { 
	unsigned char data[16];
	int size;
} iv16;

typedef struct st_iv32 { 
	unsigned char data[32];
	int size;
} iv32;

typedef struct st_aad8 { 
	unsigned char data[8];
	int size;
} aad8;

typedef struct st_aad16 { 
	unsigned char data[16];
	int size;
} aad16;

typedef struct st_aad32 { 
	unsigned char data[32];
	int size;
} aad32;

typedef struct st_tag8 { 
	unsigned char data[8];
	int size;
} tag8;

typedef struct st_tag16 { 
	unsigned char data[16];
	int size;
} tag16;

int InitKey128(key128 * key);
int InitKey192(key192 * key);
int InitKey256(key256 * key);
int InitIV8(iv8 * iv);
int InitIV16(iv16 * iv);
int InitIV32(iv32 * iv);
int InitAAD8(aad8 * iv);
int InitAAD16(aad16 * iv);
int InitAAD32(aad32 * iv);
int InitTAG8(tag8 * iv);
int InitTAG16(tag16 * iv);

int SetKey128(key128 * key, char * keyValue);
int SetKey192(key192 * key, char * keyValue);
int SetKey256(key256 * key, char * keyValue);
int SetIV8(iv8 * iv, char * ivValue);
int SetIV16(iv16 * iv, char * ivValue);
int SetIV32(iv32 * iv, char * ivValue);
int SetAAD8(aad8 * aad, char * aadValue);
int SetAAD16(aad16 * aad, char * aadValue);
int SetAAD32(aad32 * aad, char * aadValue);
int SetTAG8(tag8 * tag, char * tagValue);
int SetTAG16(tag16 * tag, char * tagValue);

int OpenFile(FILE ** handler, char * name, char * mode);

int ReadFile(FILE * handler, unsigned char ** buffer, int regsize, int blocking, int * bytesread); 

int WriteFile(FILE * handler, unsigned char * buffer, int regsize, int blocking, int * byteswritten);

int CloseFile(FILE * handler);

int DisplayChs(unsigned char * buffer, int size); 

int PrintChs(FILE * handler, unsigned char * buffer, int size, int flag); // flag = 0 => don't DisplayChs

int DisplayNibbles(unsigned char * buffer, int size); 

int DisplayHex(unsigned char * buffer, int size); 

int PrintHex(FILE * handler, unsigned char * buffer, int size, int flag); // flag = 0 => don't DisplayHex

int Generate_Key128 (key128 *k) ;

int Generate_Key192 (key192 *k) ;

int Generate_Key256 (key256 *k) ;

int Generate_Nonce8 (iv8 *iv) ;

int Generate_Nonce16 (iv16 *iv) ;

int Generate_Nonce32 (iv32 *iv) ;

// Gerar AAD

//     Aes enc;
//     Aes dec;
// 
//     const byte msg[] = { /* "Now is the time for all " w/o trailing 0 */
//         0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
//         0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
//         0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
//     };
// 
//     const byte verify[] =
//     {
//         0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
//         0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
//     };
// 
// 
//     // const byte key[] = {  // some 24 byte key };
//     byte key[] = "0123456789abcdef   ";  /* align */
// 
//     // const byte iv[] = { // some 16 byte iv };
//     byte iv[]  = "1234567890abcdef   ";  /* align */
// 
//     // byte cipher[32];
//     byte cipher[AES_BLOCK_SIZE * 4];
// 
//     // byte plain[32];   // an increment of 16, fill with data
//     byte plain [AES_BLOCK_SIZE * 4];
// 

 
#endif /* ETSS_H_ */
