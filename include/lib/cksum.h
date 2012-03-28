/*
 *  sha1.h
 *
 *	Copyright (C) 1998
 *	Paul E. Jones <paulej@arid.us>
 *	All Rights Reserved
 *
 *****************************************************************************
 *	$Id: sha1.h,v 1.2 2004/03/27 18:00:33 paulej Exp $
 *****************************************************************************
 *
 *  Description:
 *      This class implements the Secure Hashing Standard as defined
 *      in FIPS PUB 180-1 published April 17, 1995.
 *
 *      Many of the variable names in the SHA1Context, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *      Please read the file sha1.c for more information.
 *
 */
/* 
 *  This structure will hold context information for the hashing
 *  operation
 */
#ifndef __LIB_CKSUM
#define __LIB_CKSUM

#include <stdint.h>

#define SHA1_HASH_SIZE      (20)                 /* sha1 hash 160bit */
#define SHA1_HASH_STRSIZE   (SHA1_HASH_SIZE*2)   /* sha1 string hash */

unsigned long adler32(unsigned long adler, const unsigned char *buf, unsigned int len);
unsigned long crc32(unsigned long crc, const unsigned char *buf, unsigned int len);

typedef struct SHA1Context
{
    uint32_t Message_Digest[5]; /* Message Digest (output)          */
    unsigned char Message_Digest_Str[SHA1_HASH_STRSIZE]; /* Digest str (output) */

    unsigned Length_Low;        /* Message length in bits           */
    unsigned Length_High;       /* Message length in bits           */

    unsigned char Message_Block[64]; /* 512-bit message blocks      */
    int Message_Block_Index;    /* Index into message block array   */

    int Computed;               /* Is the digest computed?          */
    int Corrupted;              /* Is the message digest corruped?  */
} SHA1Context;

/*
 *  Function Prototypes
 */
void SHA1Reset(SHA1Context *);
int SHA1Result(SHA1Context *);
void SHA1Input( SHA1Context *,
                const unsigned char *,
                unsigned);
#endif

