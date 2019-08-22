
//#
//# 3DES 128 CBC (mode 2) - BoringSSL
//#

#define _POSIX_C_SOURCE 199309L

#include <openssl/des.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <time.h>

#include "etss.h"

#define PLAIN_SIZE 1024 
#define CRYPT_SIZE 1032	

key128 k;
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

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init (&ctx);
    EVP_DecryptInit_ex (&ctx, EVP_des_ede_cbc (), NULL, k.data, iv.data); 

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
        rc = EVP_DecryptUpdate (&ctx, sPureBuff, &nBytesWorked, sCiphBuff, nBytesRead);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

        dTime = (end.tv_sec - start.tv_sec);
        dTime += (end.tv_nsec - start.tv_nsec) / 1000000000.0;

		cTime += dTime;

        if ( rc != 1 ) 
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
	rc = EVP_DecryptFinal_ex (&ctx, sPureBuff + cWorked, &nBytesPad); 
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

    dTime = (end.tv_sec - start.tv_sec);
    dTime += (end.tv_nsec - start.tv_nsec) / 1000000000.0;

	cTime += dTime;

	if ( rc != 1 ) 
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

    EVP_CIPHER_CTX_cleanup (&ctx);
    
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

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init (&ctx);
    EVP_EncryptInit_ex (&ctx, EVP_des_ede_cbc (), NULL, k.data, iv.data); 

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
        rc = EVP_EncryptUpdate (&ctx, pCiphBuff, &nBytesWorked, sPureBuff, nBytesRead);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

        dTime = (end.tv_sec - start.tv_sec);
        dTime += (end.tv_nsec - start.tv_nsec) / 1000000000.0;

		cTime += dTime;

        if ( rc != 1 ) 
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
	rc = EVP_EncryptFinal_ex (&ctx, pCiphBuff, &nBytesPad);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

    dTime = (end.tv_sec - start.tv_sec);
    dTime += (end.tv_nsec - start.tv_nsec) / 1000000000.0;

    cTime += dTime;

	if ( rc != 1 ) 
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

    EVP_CIPHER_CTX_cleanup (&ctx);
    
    return 0;
}


int main (int argc, char *argv[]) 
{
	FILE *fPlain = NULL, *fEncrypt = NULL, *fDecrypt = NULL;

    k.size = 16;
	unsigned char inKey[16] = {0x9A, 0x59, 0x4E, 0xFA, 0x2C, 0x40, 0xBC, 0xC1, 0x2A, 0x05, 0x64, 0x43, 0xAC, 0x0C, 0xC1, 0xC2};

    iv.size = 16;
	unsigned char inIV[16] = {0x57, 0x1D, 0x32, 0xCE, 0x4F, 0x43, 0x17, 0x38, 0xE5, 0x52, 0x69, 0xE2, 0x18, 0xD1, 0x32, 0x09};

	strncpy((char *) k.data, (const char *) inKey, k.size);

	strncpy((char *) iv.data, (const char *) inIV, iv.size);

	int rc = 0;

    if ( (rc = OpenFile (&fPlain, argv[1], "r")) )
	{
        printf ("3DES128-B - Open input plain text file %s error (rc = %d).\n", argv[1], rc);
		return rc;
	}

    fEncrypt = fopen (argv[2], "wb+");
	rc = errno;
    if ( fEncrypt == NULL )
	{
        printf ("3DES128-B - Open output encrypt text file %s error (rc = %d).\n", argv[2], rc);
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
        printf ("3DES128-B - Open input encrypt text file %s error (rc = %d).\n", argv[2], rc);
		return rc;
	}

    if ( (rc = OpenFile (&fDecrypt, argv[3], "w")) )
	{
        printf ("3DES128-B - Open output decrypt text file %s error (rc = %d).\n", argv[3], rc);
		return rc;
	}

	printf("\n>> Decrypting...\n\n");
	Decrypta (fEncrypt, fDecrypt);

	CloseFile(fEncrypt);
	CloseFile(fDecrypt);

    return 0;
}

