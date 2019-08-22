
//#
//# AES 256 CBC - MbedTLS
//#

#define _POSIX_C_SOURCE 199309L

#include <mbedtls/cipher.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <time.h>

#include "etss.h"

#define PLAIN_SIZE 1024 
#define CRYPT_SIZE 1032	

key256 k;
iv16   iv;

int Decrypta (FILE * fInput, FILE * fOutput) 
{
	int conta = 0, rc = 0;
    int nBytesWorked = 0, nBytesPad = 0;
    int nBytesRead = 0, nBytesWritten = 0;
    int cIn = 0, cOut = 0, cWorked = 0;

    unsigned char sPureBuff[PLAIN_SIZE] __attribute__((aligned(16))), sCiphBuff[CRYPT_SIZE] __attribute__((aligned(16))); 
    unsigned char *pPureBuff __attribute__((aligned(16)));
    unsigned char *pCiphBuff __attribute__((aligned(16)));

    pPureBuff = sPureBuff;
    pCiphBuff = sCiphBuff;

	struct timespec start,end;
	double dTime, cTime = 0.0;

    mbedtls_cipher_context_t ctx;

    mbedtls_cipher_init (&ctx);

    rc = mbedtls_cipher_setup (&ctx, mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, k.size*8, MBEDTLS_MODE_CBC));

    if ( rc != 0 )
	{
		printf ("Setup - Context preparation error (rc = %d). \n", rc);
		return rc;
	} 

    rc = mbedtls_cipher_setkey (&ctx, k.data, k.size*8, MBEDTLS_DECRYPT);

    if ( rc != 0 )
	{
		printf ("Set Key - Context preparation error (rc = %d). \n", rc);
		return rc;
	} 

    rc = mbedtls_cipher_set_iv (&ctx, iv.data, iv.size);

    if ( rc != 0 )
	{
		printf ("Set IV - Context preparation error (rc = %d). \n", rc);
		return rc;
	} 

    rc = mbedtls_cipher_reset (&ctx);

    if ( rc != 0 )
	{
		printf ("Reset - Context preparation error (rc = %d). \n", rc);
		return rc;
	} 

	memset(pCiphBuff, 0, CRYPT_SIZE);
	memset(pPureBuff, 0, PLAIN_SIZE);

	if ( (rc = ReadFile (fInput, &pCiphBuff, 1, CRYPT_SIZE, &nBytesRead)) )
	{
		printf ("Decryption - Input file reading error (rc = %d). \n", rc);
		return rc;
	} 

	while ( nBytesRead > 0 )
	{
		cIn += nBytesRead;
	
		nBytesWorked = 0;

		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        rc = mbedtls_cipher_update (&ctx, sCiphBuff, nBytesRead, sPureBuff, (size_t *) &nBytesWorked);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

        dTime = (end.tv_sec - start.tv_sec);
        dTime += (end.tv_nsec - start.tv_nsec) / 1000000000.0;

        cTime += dTime;

        if ( rc != 0 ) 
		{
            printf ("Decryption - Error in DecryptUpdate() (rc = %d).\n", rc);
            return rc;
        }

		cWorked += nBytesWorked;

		// Count decryptions
		conta++;

		if ( nBytesWorked != 0 )
		{
			if ( (rc = WriteFile (fOutput, sPureBuff, 1, cWorked, &nBytesWritten)) )
			{
				printf ("Decryption - Output file writing error (rc = %d).\n", rc);
				return rc;
			}

			pPureBuff = sPureBuff;
			memset(pPureBuff, 0, PLAIN_SIZE);

			cOut += nBytesWritten;

			cWorked = 0;
		}

		if ( (rc = ReadFile (fInput, &pCiphBuff, 1, CRYPT_SIZE, &nBytesRead)) )
		{
			printf ("Decryption - Input file reading error (rc = %d). \n", rc);
			return rc;
		} 
    }

	pPureBuff += cWorked;

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
	rc = mbedtls_cipher_finish (&ctx, pPureBuff, (size_t *) &nBytesPad); 
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

    dTime = (end.tv_sec - start.tv_sec);
    dTime += (end.tv_nsec - start.tv_nsec) / 1000000000.0;

	cTime += dTime;

	if ( rc != 0 ) 
	{
		printf ("Decryption - Error in DecryptFinal() (rc=%d).\n",rc);
		return rc;
	}

    // Count decryptions
    conta++;

	cWorked += nBytesPad;

	if ( (rc = WriteFile (fOutput, sPureBuff, 1, cWorked, &nBytesWritten)) )
	{
		printf ("Decryption - Output file writing error (rc = %d).\n", rc);
		return rc;
	}

	cOut += nBytesWritten;

	// Consolidation 
	printf("\tD %d cIn = %d cOut = %d\n", conta, cIn, cOut);
	printf("\tDecryption time in miliseconds: Dt = %lf \n", cTime*1000.0);

    mbedtls_cipher_free (&ctx);
    
    return 0;
}


int Encrypta (FILE * fInput, FILE * fOutput) 
{
	int conta = 0, rc = 0;
    int nBytesWorked = 0, nBytesPad = 0;
    int nBytesRead = 0, nBytesWritten = 0;
    int cIn = 0, cOut = 0, cWorked = 0;

    unsigned char sPureBuff[PLAIN_SIZE] __attribute__((aligned(16))), sCiphBuff[CRYPT_SIZE] __attribute__((aligned(16))); 
    unsigned char *pPureBuff __attribute__((aligned(16)));
    unsigned char *pCiphBuff __attribute__((aligned(16)));

    pPureBuff = sPureBuff;
    pCiphBuff = sCiphBuff;

	struct timespec start,end;
	double dTime, cTime = 0.0;

    mbedtls_cipher_context_t ctx;

    mbedtls_cipher_init (&ctx);

    rc = mbedtls_cipher_setup (&ctx, mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, k.size*8, MBEDTLS_MODE_CBC));

    if ( rc != 0 )
	{
		printf ("Setup - Context preparation error (rc = %d). \n", rc);
		return rc;
	} 

    rc = mbedtls_cipher_setkey (&ctx, k.data, k.size*8, MBEDTLS_ENCRYPT);

    if ( rc != 0 )
	{
		printf ("Set Key - Context preparation error (rc = %d). \n", rc);
		return rc;
	} 

    rc = mbedtls_cipher_set_iv (&ctx, iv.data, iv.size);

    if ( rc != 0 )
	{
		printf ("Set IV - Context preparation error (rc = %d). \n", rc);
		return rc;
	} 

    rc = mbedtls_cipher_reset (&ctx);

    if ( rc != 0 )
	{
		printf ("Reset - Context preparation error (rc = %d). \n", rc);
		return rc;
	} 

	memset(pPureBuff, 0, PLAIN_SIZE);
	memset(pCiphBuff, 0, CRYPT_SIZE);

	if ( (rc = ReadFile (fInput, &pPureBuff, 1, PLAIN_SIZE, &nBytesRead)) )
	{
		printf ("Encryption - Input file reading error (rc = %d). \n", rc);
		return rc;
	} 

	while ( nBytesRead > 0 )
	{
		cIn += nBytesRead;
	
		pCiphBuff += cWorked;

		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        rc = mbedtls_cipher_update (&ctx, sPureBuff, nBytesRead, sCiphBuff, (size_t *) &nBytesWorked);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

        dTime = (end.tv_sec - start.tv_sec);
        dTime += (end.tv_nsec - start.tv_nsec) / 1000000000.0;

        cTime += dTime;

        if ( rc != 0 ) 
		{
            printf ("Encryption - Error in EncryptUpdate() (rc = %d).\n", rc);
            return rc;
        }

		cWorked += nBytesWorked;

        // Count encryptions
        conta++;

		if ( nBytesWorked != 0 )
		{
			if ( (rc = WriteFile (fOutput, sCiphBuff, 1, cWorked, &nBytesWritten)) )
			{
				printf ("Encryption - Output file writing error (rc = %d).\n", rc);
				return rc;
			}

			pCiphBuff = sCiphBuff;
			memset(pCiphBuff, 0, CRYPT_SIZE);

			cOut += nBytesWritten;

			cWorked = 0;
		}

		if ( (rc = ReadFile (fInput, &pPureBuff, 1, PLAIN_SIZE, &nBytesRead)) )
		{
			printf ("Encryption - Input file reading error (rc = %d). \n", rc);
			return rc;
		} 
    }
	
	pCiphBuff += cWorked;

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
	rc = mbedtls_cipher_finish (&ctx, pCiphBuff, (size_t *) &nBytesPad); 
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

    dTime = (end.tv_sec - start.tv_sec);
    dTime += (end.tv_nsec - start.tv_nsec) / 1000000000.0;

	cTime += dTime;

	if ( rc != 0 ) 
	{
		printf ("Encryption - Error in EncryptFinal() (rc=%d).\n",rc);
		return rc;
	}

    // Count encryptions
    conta++;

	cWorked += nBytesPad;

	if ( (rc = WriteFile (fOutput, sCiphBuff, 1, cWorked, &nBytesWritten)) )
	{
		printf ("Encryption - Output file writing error (rc = %d).\n", rc);
		return rc;
	}

	cOut += nBytesWritten;

	// Consolidation 
	printf("\tE %d cIn = %d cOut = %d\n", conta, cIn, cOut);
	printf("\tEncryption time in miliseconds: Et = %lf \n", cTime*1000.0);

    mbedtls_cipher_free (&ctx);
    
    return 0;
}


int main (int argc, char *argv[]) 
{
	FILE *fPlain = NULL, *fEncrypt = NULL, *fDecrypt = NULL;
                                                                                                                
    k.size = 32;
	unsigned char inKey[32] = {0xEA, 0x3E, 0x55, 0x30, 0xFA, 0x44, 0xE5, 0x2C, 0x96, 0x42, 0x33, 0xB6, 0xE9, 0xDE, 0x5D, 0xB2,
                               0xF6, 0x17, 0xB1, 0x43, 0x2D, 0xC8, 0xAA, 0xE2, 0x36, 0xC4, 0x8E, 0xF1, 0xED, 0x9C, 0xF5, 0x5E};

    iv.size = 16;
	unsigned char inIV[16] = {0x57, 0x1D, 0x32, 0xCE, 0x4F, 0x43, 0x17, 0x38, 0xE5, 0x52, 0x69, 0xE2, 0x18, 0xD1, 0x32, 0x09};

	strncpy((char *) k.data, (const char *) inKey, k.size);

	strncpy((char *) iv.data, (const char *) inIV, iv.size);

	int rc = 0;

    if ( (rc = OpenFile (&fPlain, argv[1], "r")) )
	{
        printf ("AES256-M - Open input plain text file %s error (rc = %d).\n", argv[1], rc);
		return rc;
	}

    fEncrypt = fopen (argv[2], "wb+");
	rc = errno;
    if ( fEncrypt == NULL )
	{
        printf ("AES256-M - Open output encrypt text file %s error (rc = %d).\n", argv[2], rc);
		return rc;
	}

	printf("\n>> Encrypting...\n\n");
	Encrypta (fPlain, fEncrypt);

	CloseFile(fPlain);
	CloseFile(fEncrypt);


    fEncrypt = fopen (argv[2], "rb+");
	rc = errno;
    if ( fEncrypt == NULL )
	{
        printf ("AES256-M - Open input encrypt text file %s error (rc = %d).\n", argv[2], rc);
		return rc;
	}

    if ( (rc = OpenFile (&fDecrypt, argv[3], "w")) )
	{
        printf ("AES256-M - Open output decrypt text file %s error (rc = %d).\n", argv[3], rc);
		return rc;
	}

	printf("\n>> Decrypting...\n\n");
	Decrypta (fEncrypt, fDecrypt);

	CloseFile(fEncrypt);
	CloseFile(fDecrypt);

    return 0;
}

