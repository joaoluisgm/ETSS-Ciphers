
#include <stdio.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

#include <unistd.h>
//#include <fcntl.h>
//#include <stdio.h>
//#include <sys/stat.h>
//#include <sys/types.h>

//#include <stdlib.h>

#include "etss.h"

//#define IP_SIZE 1024
//#define OP_SIZE 1032

// #define AES_256_KEY_SIZE 32
// #define AES_BLOCK_SIZE 16
// #define BUFSIZE 1024

int InitKey128(key128 * k)
{
	k->size = 16;
	memset(k->data, 0, k->size);
	return 0;
}

int InitKey192(key192 * k)
{
	k->size = 24;
	memset(k->data, 0, k->size);
	return 0;
}

int InitKey256(key256 * k)
{
	k->size = 32;
	memset(k->data, 0, k->size);
	return 0;
}

int InitIV8(iv8 * iv)
{
	iv->size = 8;
	memset(iv->data, 0, iv->size);
	return 0;
}

int InitIV16(iv16 * iv)
{
	iv->size = 16;
	memset(iv->data, 0, iv->size);
	return 0;
}

int InitIV32(iv32 * iv)
{
	iv->size = 32;
	memset(iv->data, 0, iv->size);
	return 0;
}

int InitAAD8(aad8 * aad)
{
	aad->size = 8;
	memset(aad->data, 0, aad->size);
	return 0;
}

int InitAAD16(aad16 * aad)
{
	aad->size = 16;
	memset(aad->data, 0, aad->size);
	return 0;
}

int InitAAD32(aad32 * aad)
{
	aad->size = 32;
	memset(aad->data, 0, aad->size);
	return 0;
}

int InitTAG8(tag8 * tag)
{
	tag->size = 8;
	memset(tag->data, 0, tag->size);
	return 0;
}

int InitTAG16(tag16 * tag)
{
	tag->size = 16;
	memset(tag->data, 0, tag->size);
	return 0;
}

int SetKey128(key128 * k, char * c)
{
	int i;
	for ( i = 0; i < k->size; i++ )
	{
		k->data[i] = c[i];
	}
	return 0;
}

int SetKey192(key192 * k, char * c)
{
	int i;
	for ( i = 0; i < k->size; i++ )
	{
		k->data[i] = c[i];
	}
	return 0;
}

int SetKey256(key256 * k, char * c)
{
	int i;
	for ( i = 0; i < k->size; i++ )
	{
		k->data[i] = c[i];
	}
	return 0;
}

int SetIV8(iv8 * iv, char * c)
{
	int i;
	for ( i = 0; i < iv->size; i++ )
	{
		iv->data[i] = c[i];
	}
	return 0;
}

int SetIV16(iv16 * iv, char * c)
{
	int i;
	for ( i = 0; i < iv->size; i++ )
	{
		iv->data[i] = c[i];
	}
	return 0;
}

int SetIV32(iv32 * iv, char * c)
{
	int i;
	for ( i = 0; i < iv->size; i++ )
	{
		iv->data[i] = c[i];
	}
	return 0;
}

int SetAAD8(aad8 * aad, char * c)
{
	int i;
	for ( i = 0; i < aad->size; i++ )
	{
		aad->data[i] = c[i];
	}
	return 0;
}

int SetAAD16(aad16 * aad, char * c)
{
	int i;
	for ( i = 0; i < aad->size; i++ )
	{
		aad->data[i] = c[i];
	}
	return 0;
}

int SetAAD32(aad32 * aad, char * c)
{
	int i;
	for ( i = 0; i < aad->size; i++ )
	{
		aad->data[i] = c[i];
	}
	return 0;
}

int SetTAG8(tag8 * tag, char * c)
{
	int i;
	for ( i = 0; i < tag->size; i++ )
	{
		tag->data[i] = c[i];
	}
	return 0;
}

int SetTAG16(tag16 * tag, char * c)
{
	int i;
	for ( i = 0; i < tag->size; i++ )
	{
		tag->data[i] = c[i];
	}
	return 0;
}

int OpenFile(FILE ** phandler, char * nm, char * md)
{
	int rc = 0;
	//printf("nm = <%s>, md = <%s>\n", nm, md);
    *phandler = fopen(nm, md);
	rc=errno;
	if (ferror(*phandler))
	{
		printf("fopen %s -> rc = %d\n", nm, rc);
		return rc;
    }
	//printf("fd fopen... errno = %d\n", errno);
    if ( *phandler == NULL ) 
	{
		printf("OpenFile Null handler. fopen %s -> rc = %d (Errno = %d %d)\n", nm, rc, errno, ferror(*phandler));
        return rc;
    }
	//printf("fd not NULL !!!\nrc = %d e errno = %d\n", rc, errno);
	return rc;
}

int ReadFile(FILE * handler, unsigned char ** buffer, int regsize, int blocking, int * bytesread)
{ 
	int rc = 0;
	*bytesread = fread(*buffer, regsize, blocking, handler);
	rc=errno;
	//printf("ReadFile (1) -> rc = %d\n",rc);
	//if (ferror(handler))
	//{
	if ( *bytesread != regsize * blocking && !feof(handler) )
	{
		//rc=errno;
		//printf("ReadFile (2) -> rc = %d\n",rc);
		printf("ReadFile -> rc = %d (Errno = %d)\n", rc, ferror(handler));
		printf("BytesRead = %d RegSize = %d Blocking = %d)\n", *bytesread, regsize, blocking);
		return rc;
	}
	//printf("ReadFile: bytes read = %d\n",*bytesread);
	return rc;
}

int WriteFile(FILE * handler, unsigned char * buffer, int regsize, int blocking, int * byteswritten)
{ 
	int rc = 0;
	*byteswritten = fwrite(buffer, regsize, blocking, handler);
	rc=errno;
	//printf("WriteFile (1) -> rc = %d\n",rc);
	if (ferror(handler))
	{
		//rc=errno;
		//printf("WriteFile (2) -> rc = %d\n",rc);
//		printf("WriteFile -> rc = %d\n", rc);
		printf("WriteFile -> rc = %d (Errno = %d)\n", rc, ferror(handler));
		printf("BytesWritten = %d RegSize = %d Blocking = %d)\n", *byteswritten, regsize, blocking);
		return rc;
	}
	return rc;
}

int CloseFile(FILE * handler)
{
	int rc = 0;
    rc = fclose(handler);
    //fclose(handler);
	//rc=errno;
    if (rc) 
	{
	//if (ferror(handler)){
		printf("CloseFile -> rc = %d (Errno = %d)\n",rc, ferror(handler));
        return rc;
    }
	return rc;
}

int DisplayNibbles(unsigned char * buffer, int length)
{
//	int i;
//  for (i = 0; i < length; i++)
    for (int i = 0; i < length; i++)
	{
        printf ("%02hX ", *(buffer+i));
	}
	return 0;
}

int DisplayHex(unsigned char * buffer, int length)
{
//	int i;
//  for (i = 0; i < length; i++)
    for (int i = 0; i < length; i++)
	{
        printf ("%02X ", *(buffer+i));
	}
	return 0;
}

// flag = 0 => don't DisplayHex
int PrintHex(FILE * handler, unsigned char * buffer, int length, int flag)
{
	int i;
    for (i = 0; i < length; i++)
	{
		if ( flag )
		{
			printf ("%02X ", *(buffer + i));
		}
        fprintf (handler,"%02X", *(buffer + i));
	}
	return 0;
}

int DisplayChs(unsigned char * buffer, int length)
{
	int i;
    for (i = 0; i < length; i++)
	{
        printf ("%c ", *(buffer+i));
	}
	return 0;
}

// flag = 0 => don't DisplayChs
int PrintChs(FILE * handler, unsigned char * buffer, int length, int flag)
{
	int i;
    for (i = 0; i < length; i++)
	{
		if ( flag )
		{
			printf ("%c ", *(buffer + i));
		}
        fprintf (handler,"%c", *(buffer + i));
	}
	return 0;
}

int Generate_Key128 (key128 * k) 
{
    int rc = 0, reads = 0, count = 0;
	unsigned char * pk = NULL;
	unsigned char * ps = NULL;
//	unsigned char ** pps = NULL;
	FILE *f1 = NULL, *f2 = NULL;
//	FILE ** ppf = NULL;

	InitKey128(k);

//	printf("Size of Key128 = %d\n",k->size);

	pk = k->data;
	//pps = &ps;

//	ppf = &f1;
//    rc = OpenFile (ppf, "/dev/random", "r");
    rc = OpenFile (&f1, "/dev/random", "r");
    if ( rc )
	{
		printf ("open /dev/random error. RC = %d\n", rc);
		return rc;
	}
	
	if (f1 == NULL)
	{
		printf ("f1 NULL (*) !!!\n");
		return 1;
	}
	
	//strncpy((char *) k->data,"123456789ABCDE\0",16);
	//count = 4;
	//printf("Vai !!!\n");

	while ( count < k->size )
	{
//		printf(" k->data => %p count = %d k->data + count %p k->size - count %d\n", k->data, count, (k->data + count), (k->size - count));
//		printf(" k->data => %s \n", k->data);

		//ps = k->data + 1;
		////ps = dps + count;
		//printf("Foi !!!\n");
		////*pps = (k->data + count);
		////*pps = &k->data[0];
		//pps = &ps;
		//printf(" k->data => %p ps = %s *ps = %c *pps = %p **pps = %c\n", k->data, ps, *ps, *pps, **pps);
		//printf("Morreu !!!\n");
		//exit(999);

		//*pps = k->data[count];
		//ps = k->data + count;
		ps = pk + count;
//		printf("2k->data => %p count = %d k->data + count %p k->size - count %d\n", k->data, count, k->data + count, k->size - count);
//		printf(" k->data => %p count = %d ps = %p k->size - count %d\n", k->data, count, ps, k->size - count);
		//if ((rc = ReadFile (f1, &(k->data + count), 1, k->size - count, &reads))){
//		pps = &ps;
//		if ((rc = ReadFile (f1, pps, 1, k->size - count, &reads)))
		if ((rc = ReadFile (f1, &ps, 1, k->size - count, &reads)))
		{
			printf ("read key128 error. RC = %d\n", rc);
			return rc;
		}
		count += reads;
		//count += reads + 10;  // Usado nos testes quando os erros da OpenFile
	}

//	ppf = &f2;
//    rc = OpenFile (ppf, "msgFile.txt", "w");
    rc = OpenFile (&f2, "msgFile.txt", "w");
    if ( rc )
	{
        printf ("open key file error. RC = %d\n", rc);
		return rc;
	}
//	// Retirar depois
//	if (*ppf == NULL)
//	{
//		printf ("f2 NULL (**) !!!\n");
//		//return 1;
//	}
	if (f2 == NULL)
	{
		printf ("f2 NULL (*) !!!\n");
		return 1;
	}
	
//    printf("128 bit key (per byte in Hexa):\n\n");
    printf("Key 128 bits: \n\tSize = %d \n\tKey = ",k->size);

    fprintf (f2,"\n128 bits key: ");
	PrintHex(f2, k->data, k->size, 1); // flag = 1 => DisplayHex
	fprintf (f2,"\n\n");

//    printf("\n");
////	DisplayChs(k->data, k->size);
//    fprintf (f2,"    ");
//	  PrintChs(f2, k->data, k->size, 1); // flag = 1 => DisplayChs
//    printf("\n");

	
    printf ("\n ------ \n");

	CloseFile(f1);
	CloseFile(f2);
    return rc;
}

int Generate_Key192 (key192 * k) 
{
    int rc = 0, reads = 0, count = 0;
	unsigned char * pk = NULL;
	unsigned char * ps = NULL;
//	unsigned char ** pps = NULL;
	FILE *f1 = NULL, *f2 = NULL;
//	FILE ** ppf = NULL;

	InitKey192(k);

//	printf("Size of Key192 = %d\n",k->size);

	pk = k->data;
	//pps = &ps;

//	ppf = &f1;
//    rc = OpenFile (ppf, "/dev/random", "r");
    rc = OpenFile (&f1, "/dev/random", "r");
    if ( rc )
	{
		printf ("open /dev/random error. RC = %d\n", rc);
		return rc;
	}
	
	if (f1 == NULL)
	{
		printf ("f1 NULL (*) !!!\n");
		return 1;
	}
	
	//strncpy((char *) k->data,"123456789ABCDE\0",16);
	//count = 4;
	//printf("Vai !!!\n");

	while ( count < k->size )
	{
//		printf(" k->data => %p count = %d k->data + count %p k->size - count %d\n", k->data, count, (k->data + count), (k->size - count));
//		printf(" k->data => %s \n", k->data);

		//ps = k->data + 1;
		////ps = dps + count;
		//printf("Foi !!!\n");
		////*pps = (k->data + count);
		////*pps = &k->data[0];
		//pps = &ps;
		//printf(" k->data => %p ps = %s *ps = %c *pps = %p **pps = %c\n", k->data, ps, *ps, *pps, **pps);
		//printf("Morreu !!!\n");
		//exit(999);

		//*pps = k->data[count];
		//ps = k->data + count;
		ps = pk + count;
//		printf("2k->data => %p count = %d k->data + count %p k->size - count %d\n", k->data, count, k->data + count, k->size - count);
//		printf(" k->data => %p count = %d ps = %p k->size - count %d\n", k->data, count, ps, k->size - count);
		//if ((rc = ReadFile (f1, &(k->data + count), 1, k->size - count, &reads))){
//		pps = &ps;
//		if ((rc = ReadFile (f1, pps, 1, k->size - count, &reads)))
		if ((rc = ReadFile (f1, &ps, 1, k->size - count, &reads)))
		{
			printf ("read key192 error. RC = %d\n", rc);
			return rc;
		}
		count += reads;
		//count += reads + 10;  // Usado nos testes quando os erros da OpenFile
	}

//	ppf = &f2;
//    rc = OpenFile (ppf, "msgFile.txt", "w");
    rc = OpenFile (&f2, "msgFile.txt", "w");
    if ( rc )
	{
        printf ("open key file error. RC = %d\n", rc);
		return rc;
	}
//	// Retirar depois
//	if (*ppf == NULL)
//	{
//		printf ("f2 NULL (**) !!!\n");
//		//return 1;
//	}
	if (f2 == NULL)
	{
		printf ("f2 NULL (*) !!!\n");
		return 1;
	}
	
//    printf("192 bit key (per byte in Hexa):\n\n");
    printf("Key 192 bits: \n\tSize = %d \n\tKey = ",k->size);

    fprintf (f2,"\n192 bits key: ");
	PrintHex(f2, k->data, k->size, 1); // flag = 1 => DisplayHex
	fprintf (f2,"\n\n");

//    printf("\n");
////	DisplayChs(k->data, k->size);
//    fprintf (f2,"    ");
//	  PrintChs(f2, k->data, k->size, 1); // flag = 1 => DisplayChs
//    printf("\n");

	
    printf ("\n ------ \n");

	CloseFile(f1);
	CloseFile(f2);
    return rc;
}

int Generate_Key256 (key256 *k) 
{
    int rc = 0, reads = 0, count = 0;
	unsigned char * pk = NULL;
	unsigned char * ps = NULL;
//	unsigned char ** pps = NULL;
	FILE *f1 = NULL, *f2 = NULL;
//	FILE ** ppf = NULL;

	InitKey256(k);

//	printf("Size of Key256 = %d\n",k->size);

	pk = k->data;

//	ppf = &f1;
//    rc = OpenFile (ppf, "/dev/random", "r");
    rc = OpenFile (&f1, "/dev/random", "r");
    if ( rc )
	{
        printf ("open /dev/random error. RC = %d\n", rc);
		return rc;
	}

	if (f1 == NULL)
	{
		printf ("f1 NULL (*) !!!\n");
		return 1;
	}
	
	while ( count < k->size )
	{
//		printf(" k->data => %p count = %d k->data + count %p\n", k->data, count, k->data + count);
		//*pps = k->data + count;
		ps = pk + count;
//		pps = &ps;
//		//if ((rc = ReadFile (f1, &(k->data + count), 1, k->size - count, &reads))){
//		if ((rc = ReadFile (f1, pps, 1, k->size - count, &reads)))
		if ((rc = ReadFile (f1, &ps, 1, k->size - count, &reads)))
		{
			printf ("read key256 error. RC = %d\n", rc);
			return rc;
		}
		count += reads;
	}

//	ppf = &f2;
//    rc = OpenFile (ppf, "msgFile.txt", "w");
    rc = OpenFile (&f2, "msgFile.txt", "w");
    if ( rc )
	{
        printf ("open key file error. RC = %d\n", rc);
		return rc;
	}

	if (f2 == NULL)
	{
		printf ("f2 NULL (*) !!!\n");
		return 1;
	}
	
//    printf("256 bit key (per byte in Hexa):\n");
//    printf("256 bit key (per byte in Hexa): ");
    printf("Key 256 bits: \n\tSize = %d \n\tKey = ",k->size);

    fprintf (f2,"\n256 bits key: ");
	PrintHex(f2, k->data, k->size, 1); // flag = 1 => DisplayHex
    fprintf (f2,"\n\n");

    printf ("\n ------ \n");
    
	CloseFile(f1);
	CloseFile(f2);
    return rc;
}

int Generate_Nonce8 (iv8 *iv) 
{
    int rc = 0, reads = 0, count = 0;
	unsigned char * pk = NULL;
	unsigned char * ps = NULL;
//	unsigned char ** pps = NULL;
	FILE *f1 = NULL, *f2 = NULL;
//	FILE ** ppf = NULL;

	InitIV8(iv);

//	printf("Size of IV8 = %d\n",iv->size);

	pk = iv->data;

//	ppf = &f1;
//    rc = OpenFile (ppf, "/dev/random", "r");
    rc = OpenFile (&f1, "/dev/random", "r");
    if ( rc )
	{
        printf ("open /dev/random error. RC = %d\n", rc);
		return rc;
	}

	while ( count < iv->size )
	{
//		printf(" iv->data => %p count = %d iv->data + count %p\n", iv->data, count,iv->data + count);
		////*pps = (iv->data + count);
		//*pps = iv->data + count;
		ps = pk + count;
//		pps = &ps;
		//if ((rc = ReadFile (f1, &(iv->data + count), 1, iv->size - count, &reads))){
//		if ((rc = ReadFile (f1, pps, 1, iv->size - count, &reads)))
		if ((rc = ReadFile (f1, &ps, 1, iv->size - count, &reads)))
		{
			printf ("read iv error. RC = %d\n", rc);
			return rc;
		}
		count += reads;
	}

//	ppf = &f2;
//    rc = OpenFile (ppf, "msgFile.txt", "a");
    rc = OpenFile (&f2, "msgFile.txt", "a");
    if ( rc )
	{
        printf ("open nonce file error. RC = %d\n", rc);
		return rc;
	}

//    printf("Initialization vector (8 bytes in Hexa):\n");
    printf("IV (8 bytes): \n\tSize = %d \n\tKey = ",iv->size);

    fprintf (f2,"IV (8 Bytes): ");
	PrintHex(f2, iv->data, iv->size, 1); // flag = 1 => DisplayHex
    fprintf (f2,"\n\n");

    printf ("\n ------ \n");

	CloseFile(f1);
	CloseFile(f2);
    return rc;
}

int Generate_Nonce16 (iv16 *iv) 
{
    int rc = 0, reads = 0, count = 0;
	unsigned char * pk = NULL;
	unsigned char * ps = NULL;
//	unsigned char ** pps = NULL;
	FILE *f1 = NULL, *f2 = NULL;
//	FILE ** ppf = NULL;

	InitIV16(iv);

//	printf("Size of IV16 = %d\n",iv->size);

	pk = iv->data;

//	ppf = &f1;
//    rc = OpenFile (ppf, "/dev/random", "r");
    rc = OpenFile (&f1, "/dev/random", "r");
    if ( rc )
	{
        printf ("open /dev/random error. RC = %d\n", rc);
		return rc;
	}

	while ( count < iv->size )
	{
//		printf(" iv->data => %p count = %d iv->data + count %p\n", iv->data, count,iv->data + count);
		//*pps = iv->data + count;
		ps = pk + count;
//		pps = &ps;
		//if ((rc = ReadFile (f1, &(iv->data + count), 1, iv->size - count, &reads))){
//		if ((rc = ReadFile (f1, pps, 1, iv->size - count, &reads)))
		if ((rc = ReadFile (f1, &ps, 1, iv->size - count, &reads)))
		{
			printf ("read iv error. RC = %d\n", rc);
			return rc;
		}
		count += reads;
	}

//	ppf = &f2;
//    rc = OpenFile (ppf, "msgFile.txt", "a");
    rc = OpenFile (&f2, "msgFile.txt", "a");
    if ( rc )
	{
        printf ("open nonce file error. RC = %d\n", rc);
		return rc;
	}

//    printf("Initialization vector (16 bytes in Hexa):\n");
//    printf("IV (16 bytes): ");
    printf("IV (16 bytes): \n\tSize = %d \n\tKey = ",iv->size);

    fprintf (f2,"IV (16 Bytes): ");
	PrintHex(f2, iv->data, iv->size, 1); // flag = 1 => DisplayHex
    fprintf (f2,"\n\n");

    printf ("\n ------ \n");

	CloseFile(f1);
	CloseFile(f2);
    return 0;
}

int Generate_Nonce32 (iv32 *iv) 
{
    int rc = 0, reads = 0, count = 0;
	unsigned char * pk = NULL;
	unsigned char * ps = NULL;
//	unsigned char ** pps = NULL;
	FILE *f1 = NULL, *f2 = NULL;
//	FILE ** ppf = NULL;

	InitIV32(iv);

//	printf("Size of IV16 = %d\n",iv->size);

	pk = iv->data;

//	ppf = &f1;
//    rc = OpenFile (ppf, "/dev/random", "r");
    rc = OpenFile (&f1, "/dev/random", "r");
    if ( rc )
	{
        printf ("open /dev/random error. RC = %d\n", rc);
		return rc;
	}

	while ( count < iv->size )
	{
//		printf(" iv->data => %p count = %d iv->data + count %p\n", iv->data, count,iv->data + count);
		//*pps = iv->data + count;
		ps = pk + count;
//		pps = &ps;
		//if ((rc = ReadFile (f1, &(iv->data + count), 1, iv->size - count, &reads))){
//		if ((rc = ReadFile (f1, pps, 1, iv->size - count, &reads)))
		if ((rc = ReadFile (f1, &ps, 1, iv->size - count, &reads)))
		{
			printf ("read iv error. RC = %d\n", rc);
			return rc;
		}
		count += reads;
	}

//	ppf = &f2;
//    rc = OpenFile (ppf, "msgFile.txt", "a");
    rc = OpenFile (&f2, "msgFile.txt", "a");
    if ( rc )
	{
        printf ("open nonce file error. RC = %d\n", rc);
		return rc;
	}

//    printf("Initialization vector (16 bytes in Hexa):\n");
//    printf("IV (16 bytes): ");
    printf("IV (32 bytes): \n\tSize = %d \n\tKey = ",iv->size);

    fprintf (f2,"IV (32 Bytes): ");
	PrintHex(f2, iv->data, iv->size, 1); // flag = 1 => DisplayHex
    fprintf (f2,"\n\n");

    printf ("\n ------ \n");

	CloseFile(f1);
	CloseFile(f2);
    return 0;
}



