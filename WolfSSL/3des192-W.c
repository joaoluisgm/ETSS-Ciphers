
//#
//# 3DES 192 CBC - WolfSSL
//#

#include <wolfssl/openssl/evp.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "etss.h"

#define PLAIN_SIZE 1024
#define CRYPT_SIZE 1024

key192 k;
iv8    iv;

int Decrypta (FILE * fInput, FILE * fOutput) 
{
    unsigned char sPureBuff[PLAIN_SIZE] __attribute__((aligned(16))), sCiphBuff[CRYPT_SIZE] __attribute__((aligned(16))); 
    unsigned char *pPureBuff __attribute__((aligned(16)));
    unsigned char *pCiphBuff __attribute__((aligned(16)));

	int conta = 0, rc = 0;
    int nBytesWorked = 0, nBytesPad = 0;
    int nBytesRead = 0, nBytesWritten = 0;
    int cIn = 0, cOut = 0, cWorked = 0;

    pPureBuff = sPureBuff;
    pCiphBuff = sCiphBuff;

    wolfCrypt_Init();

    WOLFSSL_EVP_CIPHER_CTX ctx;
    wolfSSL_EVP_CIPHER_CTX_init (&ctx);

    wolfSSL_EVP_CIPHER_CTX_set_padding(&ctx, 1);

    wolfSSL_EVP_CipherInit_ex (&ctx, wolfSSL_EVP_des_ede3_cbc (), NULL, k.data, iv.data, 0); 

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

        rc = wolfSSL_EVP_CipherUpdate (&ctx, pPureBuff, &nBytesWorked, sCiphBuff, nBytesRead);

        if ( rc != 1 ) 
		{
            printf ("Decryption - Error in CipherUpdate() (rc = %d).\n", rc);
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

	rc = wolfSSL_EVP_CipherFinal (&ctx, pPureBuff, &nBytesPad); 

	if ( rc != 1 ) 
	{
		printf ("Decryption - Error in CipherFinal() (rc=%d).\n",rc);
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

    wolfSSL_EVP_CIPHER_CTX_cleanup (&ctx);
    
    return 0;
}


int Encrypta (FILE * fInput, FILE * fOutput) 
{
    unsigned char sPureBuff[PLAIN_SIZE] __attribute__((aligned(16))), sCiphBuff[CRYPT_SIZE] __attribute__((aligned(16))); 
    unsigned char *pPureBuff __attribute__((aligned(16)));
    unsigned char *pCiphBuff __attribute__((aligned(16)));

	int conta = 0, rc = 0;
    int nBytesWorked = 0, nBytesPad = 0;
    int nBytesRead = 0, nBytesWritten = 0;
    int cIn = 0, cOut = 0, cWorked = 0;

    pPureBuff = sPureBuff;
    pCiphBuff = sCiphBuff;

    wolfCrypt_Init();

    WOLFSSL_EVP_CIPHER_CTX ctx;
    wolfSSL_EVP_CIPHER_CTX_init (&ctx);

    wolfSSL_EVP_CIPHER_CTX_set_padding(&ctx, 1);

    wolfSSL_EVP_CipherInit_ex (&ctx, wolfSSL_EVP_des_ede3_cbc (), NULL, k.data, iv.data, 1); 

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
	
        nBytesWorked = 0;

        rc = wolfSSL_EVP_CipherUpdate (&ctx, pCiphBuff, &nBytesWorked, sPureBuff, nBytesRead);

        if ( rc != 1 ) 
		{
            printf ("Encryption - Error in CipherUpdate() (rc = %d).\n", rc);
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

	rc = wolfSSL_EVP_CipherFinal (&ctx, pCiphBuff, &nBytesPad);

	if ( rc != 1 ) 
	{
		printf ("Encryption - Error in CipherFinal() (rc=%d).\n",rc);
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

    wolfSSL_EVP_CIPHER_CTX_cleanup (&ctx);
    
    return 0;
}


int main (int argc, char *argv[]) 
{
	FILE *fPlain = NULL, *fEncrypt = NULL, *fDecrypt = NULL;

    k.size = 24;
	unsigned char inKey[24] = {0xEA, 0x3E, 0x55, 0xFA, 0x44, 0xE5, 0x96, 0x42, 0x33, 0xE9, 0xDE, 0x5D,
                               0xF6, 0x17, 0xB1, 0x2D, 0xC8, 0xAA, 0x36, 0xC4, 0x8E, 0xED, 0x9C, 0xF5};

    iv.size = 8;
	unsigned char inIV[8] = {0x7D, 0x3C, 0xF3, 0x13, 0x52, 0x6E, 0x81, 0x30};

	strncpy((char *) k.data, (const char *) inKey, k.size);

	strncpy((char *) iv.data, (const char *) inIV, iv.size);

	int rc = 0;

    if ( (rc = OpenFile (&fPlain, argv[1], "r")) )
	{
        printf ("3DES192-W - Open input plain text file %s error (rc = %d).\n", argv[1], rc);
		return rc;
	}

    fEncrypt = fopen (argv[2], "wb+");
	rc = errno;
    if ( fEncrypt == NULL )
	{
        printf ("3DES192-W - Open output encrypt text file %s error (rc = %d).\n", argv[2], rc);
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
        printf ("3DES192-W - Open input encrypt text file %s error (rc = %d).\n", argv[2], rc);
		return rc;
	}

    if ( (rc = OpenFile (&fDecrypt, argv[3], "w")) )
	{
        printf ("3DES192-W - Open output decrypt text file %s error (rc = %d).\n", argv[3], rc);
		return rc;
	}

	printf("\n>> Decrypting...\n\n");
	Decrypta (fEncrypt, fDecrypt);

	CloseFile(fEncrypt);
	CloseFile(fDecrypt);

    return 0;
}

