
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <syslog.h>
#include <time.h> 
#include <openssl/engine.h>
struct block{
ECDSA_SIG *signature;
ECDSA_SIG *bksignature;
EC_KEY *eckey;
EC_KEY *bkeckey;
unsigned char *filename;
int index;

}*head;
struct block *block2;
struct block *block3;
struct block *block4;
struct block *block5;
unsigned char* toString(struct block b)
{
  unsigned char *str=malloc(sizeof(unsigned char)*sizeof(b));
  memcpy(str,&b,sizeof(b));
  return str;
}
void addBlock(ECDSA_SIG *signature,EC_KEY *eckey,char *filename,int ind)
{
if(ind==0)
  { 
int function_status = -1;
char *hash1=(char *)malloc(SHA512_DIGEST_LENGTH);
    head=malloc(sizeof(struct block)+sizeof(char [strlen(filename)]));
SHA512("", sizeof(""), hash1);
EC_KEY *bkeckey1=EC_KEY_new();
ECDSA_SIG *bksignature1;
    if (NULL == bkeckey1)
    {
        printf("Failed to create new EC Key\n");
        function_status = -1;
    }
    else
    {
        EC_GROUP *ecgroup1= EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (NULL == ecgroup1)
        {
            printf("Failed to create new EC Group\n");
            function_status = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(bkeckey1,ecgroup1);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
                function_status = -1;
            }
           else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(bkeckey1);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                    function_status = -1;
                }
                else
                {
                    bksignature1 = ECDSA_do_sign(hash1, strlen(hash1), bkeckey1);
                    if (NULL == bksignature1)
                    {
                        printf("Failed to generate EC Signature\n");
                        function_status = -1;
                    }
                }
            }
            //EC_GROUP_free(ecgroup1);
        }
       // EC_KEY_free(bkeckey1);
    }
//printf("\n signature  is %s \n",signature);
head->signature=signature ;
//printf("\n signature  is %s \n",head->signature);
head->bksignature=bksignature1;
//printf("\n blck signature  is %s \n",head->bksignature);
head->eckey=eckey;
head->bkeckey=bkeckey1;
head->filename=filename;
head->index=ind;
 }
else if(ind==1)
{
int function_status2 = -1;
char *hash2=(char *)malloc(SHA512_DIGEST_LENGTH);
    block2=malloc(sizeof(struct block)+sizeof(char [strlen(filename)]));
SHA512(toString(*head),sizeof(*head), hash2);
EC_KEY *bkeckey2=EC_KEY_new();
ECDSA_SIG *bksignature2;
    if (NULL == bkeckey2)
    {
        printf("Failed to create new EC Key\n");
        function_status2 = -1;
    }
    else
    {
        EC_GROUP *ecgroup2= EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (NULL == ecgroup2)
        {
            printf("Failed to create new EC Group\n");
            function_status2 = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(bkeckey2,ecgroup2);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
                function_status2 = -1;
            }
           else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(bkeckey2);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                    function_status2 = -1;
                }
                else
                {
                    bksignature2 = ECDSA_do_sign(hash2, strlen(hash2), bkeckey2);
                    if (NULL == bksignature2)
                    {
                        printf("Failed to generate EC Signature\n");
                        function_status2 = -1;
                    }
                }
            }
            //EC_GROUP_free(ecgroup1);
        }
       // EC_KEY_free(bkeckey1);
    }
//printf("\n signature  is %s \n",signature);
block2->signature=signature ;
//printf("\n signature  is %s \n",block2->signature);
block2->bksignature=bksignature2;
//printf("\n blck signature  is %s \n",block2->bksignature);
block2->eckey=eckey;
block2->bkeckey=bkeckey2;
block2->filename=filename;
block2->index=ind;
 }  
else if(ind==2)
{
int function_status3 = -1;
char *hash3=(char *)malloc(SHA512_DIGEST_LENGTH);
block3=malloc(sizeof(struct block)+sizeof(char [strlen(filename)]));
SHA512(toString(*block2),sizeof(*block2), hash3);
EC_KEY *bkeckey3=EC_KEY_new();
ECDSA_SIG *bksignature3;
    if (NULL == bkeckey3)
    {
        printf("Failed to create new EC Key\n");
        function_status3 = -1;
    }
    else
    {
        EC_GROUP *ecgroup3= EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (NULL == ecgroup3)
        {
            printf("Failed to create new EC Group\n");
            function_status3 = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(bkeckey3,ecgroup3);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
                function_status3 = -1;
            }
           else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(bkeckey3);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                    function_status3 = -1;
                }
                else
                {
                    bksignature3 = ECDSA_do_sign(hash3, strlen(hash3), bkeckey3);
                    if (NULL == bksignature3)
                    {
                        printf("Failed to generate EC Signature\n");
                        function_status3 = -1;
                    }
                }
            }
            //EC_GROUP_free(ecgroup1);
        }
       // EC_KEY_free(bkeckey1);
    }
//printf("\n signature  is %s \n",signature);
block3->signature=signature ;
//printf("\n signature  is %s \n",block3->signature);
block3->bksignature=bksignature3;
//printf("\n blck signature  is %s \n",block3->bksignature);
block3->eckey=eckey;
block3->bkeckey=bkeckey3;
block3->filename=filename;
block3->index=ind;
 }  
else if(ind==3)
{
int function_status4 = -1;
char *hash4=(char *)malloc(SHA512_DIGEST_LENGTH);
    block4=malloc(sizeof(struct block)+sizeof(char [strlen(filename)]));
SHA512(toString(*block3),sizeof(*block3), hash4);
EC_KEY *bkeckey4=EC_KEY_new();
ECDSA_SIG *bksignature4;
    if (NULL == bkeckey4)
    {
        printf("Failed to create new EC Key\n");
        function_status4 = -1;
    }
    else
    {
        EC_GROUP *ecgroup4= EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (NULL == ecgroup4)
        {
            printf("Failed to create new EC Group\n");
            function_status4 = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(bkeckey4,ecgroup4);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
                function_status4 = -1;
            }
           else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(bkeckey4);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                    function_status4 = -1;
                }
                else
                {
                    bksignature4 = ECDSA_do_sign(hash4, strlen(hash4), bkeckey4);
                    if (NULL == bksignature4)
                    {
                        printf("Failed to generate EC Signature\n");
                        function_status4 = -1;
                    }
                }
            }
            //EC_GROUP_free(ecgroup1);
        }
       // EC_KEY_free(bkeckey1);
    }
//printf("\n signature  is %s \n",signature);
block4->signature=signature ;
//printf("\n signature  is %s \n",block4->signature);
block4->bksignature=bksignature4;
//printf("\n blck signature  is %s \n",block4->bksignature);
block4->eckey=eckey;
block4->bkeckey=bkeckey4;
block4->filename=filename;
block4->index=ind;
 }  
else if(ind==4)
{
int function_status5 = -1;
char *hash5=(char *)malloc(SHA512_DIGEST_LENGTH);
    block5=malloc(sizeof(struct block)+sizeof(char [strlen(filename)]));
SHA512(toString(*block4),sizeof(*block4), hash5);
EC_KEY *bkeckey5=EC_KEY_new();
ECDSA_SIG *bksignature5;
    if (NULL == bkeckey5)
    {
        printf("Failed to create new EC Key\n");
        function_status5 = -1;
    }
    else
    {
        EC_GROUP *ecgroup5= EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (NULL == ecgroup5)
        {
            printf("Failed to create new EC Group\n");
            function_status5= -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(bkeckey5,ecgroup5);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
                function_status5 = -1;
            }
           else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(bkeckey5);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                    function_status5 = -1;
                }
                else
                {
                    bksignature5 = ECDSA_do_sign(hash5, strlen(hash5), bkeckey5);
                    if (NULL == bksignature5)
                    {
                        printf("Failed to generate EC Signature\n");
                        function_status5 = -1;
                    }
                }
            }
            //EC_GROUP_free(ecgroup1);
        }
       // EC_KEY_free(bkeckey1);
    }
//printf("\n signature  is %s \n",signature);
block5->signature=signature ;
//printf("\n signature  is %s \n",block5->signature);
block5->bksignature=bksignature5;
//printf("\n blck signature  is %s \n",block5->bksignature);
block5->eckey=eckey;
block5->bkeckey=bkeckey5;
block5->filename=filename;
block5->index=ind;
 }  

  }
void verifyBlock(int n)
{
if(n==0)
{
clock_t tic1 = clock();
char *hashv1=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512("", sizeof(""), hashv1);
int verify_statusb = ECDSA_do_verify(hashv1, strlen(hashv1), head->bksignature, head->bkeckey);
//printf("status is %d ",verify_statusb);
char *path=head->filename;
FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        printf("Error: Invalid file.\n");
        //return;
    }
    
    long int fSize = 0;
    
    fseek(f, 0, SEEK_END);
   fSize = ftell(f);
    fseek(f, 0, SEEK_SET);
 unsigned char *fContents = (unsigned char*) malloc(sizeof(char) * fSize);

   size_t amountReadf = fread(fContents, fSize, 1, f);

char *hashf=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512(fContents, sizeof(fContents), hashf);
EC_KEY *headeckey= head->eckey;
//printf("\n ecey  is %s \n",eckey);
//printf("\n ecey  is %s \n",head->eckey);
ECDSA_SIG *headsignature=head->signature;
int verify_status = ECDSA_do_verify(hashf, strlen(hashf), headsignature, headeckey);
const int verify_success = 1;
if (verify_success != verify_status)
{
 printf("Failed to verify EC Signature\n");
}
else
{
printf("verified");
}

//printf("\n hash of video is%s\n",hashf);
clock_t toc1 = clock();
printf("Elapsed: %f seconds\n", (double)(toc1 - tic1) / CLOCKS_PER_SEC);
}
else if(n==1)
{
clock_t tic2 = clock();
char *hashv2=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512(toString(*head),sizeof(*head), hashv2);
int verify_statusb2 = ECDSA_do_verify(hashv2, strlen(hashv2), block2->bksignature, block2->bkeckey);
//printf("status is %d ",verify_statusb2);
char *path2=block2->filename;
FILE *f2 = fopen(path2, "rb");
    if (f2 == NULL)
    {
        printf("Error: Invalid file.\n");
        //return;
    }
    
    long int fSize2 = 0;
    
    fseek(f2, 0, SEEK_END);
   fSize2 = ftell(f2);
    fseek(f2, 0, SEEK_SET);
 unsigned char *fContents2 = (unsigned char*) malloc(sizeof(char) * fSize2);

   size_t amountReadf2 = fread(fContents2, fSize2, 1, f2);

char *hashf2=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512(fContents2, sizeof(fContents2), hashf2);
int verify_status2 = ECDSA_do_verify(hashf2, strlen(hashf2), block2->signature, block2->eckey);
const int verify_success = 1;
if (verify_success != verify_status2)
{
 printf("Failed to verify EC Signature\n");
}
else
{
printf("verified");
}

//printf("\n hash of video is%s\n",hashf2);
clock_t toc2 = clock();

  
    
printf("Elapsed: %f seconds\n", (double)(toc2 - tic2) / CLOCKS_PER_SEC);
}
else if(n==2)
{
clock_t tic3 = clock();
char *hashv3=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512(toString(*block2),sizeof(*block2), hashv3);
int verify_statusb3 = ECDSA_do_verify(hashv3, strlen(hashv3), block3->bksignature, block3->bkeckey);
//printf("status is %d ",verify_statusb3);
char *path3=block3->filename;
FILE *f3 = fopen(path3, "rb");
    if (f3 == NULL)
    {
        printf("Error: Invalid file.\n");
        //return;
    }
    
    long int fSize3 = 0;
    
    fseek(f3, 0, SEEK_END);
   fSize3 = ftell(f3);
    fseek(f3, 0, SEEK_SET);
 unsigned char *fContents3= (unsigned char*) malloc(sizeof(char) * fSize3);

   size_t amountReadf3 = fread(fContents3, fSize3, 1, f3);
char *hashf3=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512(fContents3, sizeof(fContents3), hashf3);
int verify_status3 = ECDSA_do_verify(hashf3, strlen(hashf3), block3->signature, block3->eckey);
const int verify_success = 1;
if (verify_success != verify_status3)
{
 printf("Failed to verify EC Signature\n");
}
else
{
printf("verified");
}

//printf("\n hash of video is%s\n",hashf3);
clock_t toc3 = clock();
printf("Elapsed: %f seconds\n", (double)(toc3 - tic3) / CLOCKS_PER_SEC);
}
else if(n==3)
{
clock_t tic4 = clock();
char *hashv4=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512(toString(*block3),sizeof(*block3), hashv4);
int verify_statusb4 = ECDSA_do_verify(hashv4, strlen(hashv4), block4->bksignature, block4->bkeckey);
//printf("status is %d ",verify_statusb4);
char *path4=block4->filename;
FILE *f4= fopen(path4, "rb");
    if (f4 == NULL)
    {
        printf("Error: Invalid file.\n");
        //return;
    }
    
    long int fSize4 = 0;
    
    fseek(f4, 0, SEEK_END);
   fSize4 = ftell(f4);
    fseek(f4, 0, SEEK_SET);
 unsigned char *fContents4= (unsigned char*) malloc(sizeof(char) * fSize4);

   size_t amountReadf4= fread(fContents4, fSize4, 1, f4);

char *hashf4=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512(fContents4, sizeof(fContents4), hashf4);
int verify_status4= ECDSA_do_verify(hashf4, strlen(hashf4), block4->signature, block4->eckey);
const int verify_success = 1;
if (verify_success != verify_status4)
{
 printf("Failed to verify EC Signature\n");
}
else
{
printf("verified");
}

//printf("\n hash of video is%s\n",hashf4);
clock_t toc4 = clock();
printf("Elapsed: %f seconds\n", (double)(toc4 - tic4) / CLOCKS_PER_SEC);
}
else if(n==4)
{
clock_t tic5 = clock();
char *hashv5=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512(toString(*block4),sizeof(*block4), hashv5);
int verify_statusb5 = ECDSA_do_verify(hashv5, strlen(hashv5), block5->bksignature, block5->bkeckey);
//printf("status is %d ",verify_statusb5);
char *path5=block5->filename;
FILE *f5= fopen(path5, "rb");
    if (f5 == NULL)
    {
        printf("Error: Invalid file.\n");
        //return;
    }
    
    long int fSize5 = 0;
    
    fseek(f5, 0, SEEK_END);
   fSize5 = ftell(f5);
    fseek(f5, 0, SEEK_SET);
 unsigned char *fContents5= (unsigned char*) malloc(sizeof(char) * fSize5);

   size_t amountReadf5= fread(fContents5, fSize5, 1, f5);

char *hashf5=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512(fContents5, sizeof(fContents5), hashf5);
int verify_status5= ECDSA_do_verify(hashf5, strlen(hashf5), block5->signature, block5->eckey);
const int verify_success = 1;
if (verify_success != verify_status5)
{
 printf("Failed to verify EC Signature\n");
}
else
{
printf("verified");
}

//printf("\n hash of video is%s\n",hashf5);
clock_t toc5 = clock();
printf("Elapsed: %f seconds\n", (double)(toc5 - tic5) / CLOCKS_PER_SEC);
}
}
int main( int argc , char * argv[] )
{
int ind=0;
int ch,n;
while(1)
{
printf("enter the number 1)add blocks 2)veriy block");
scanf("%d",&ch);
switch(ch)
{

case 1:printf("add block");
unsigned char *filename1=(unsigned char *)malloc(17);
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename1);

clock_t tic = clock();
FILE *file = fopen(filename1, "rb");
if (file == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize = 0;
    
    fseek(file, 0, SEEK_END);
   fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
 unsigned char *fileContents = (unsigned char*) malloc(sizeof(char) * fileSize);
   size_t amountRead = fread(fileContents, fileSize, 1, file);
char *hash=(char *)malloc(SHA512_DIGEST_LENGTH);
SHA512(fileContents, sizeof(fileContents), hash);
//printf("\n hash of video is%s\n",hash);
//printf("sha length is%d\n",sizeof(hash));
 
int function_status = -1;
EC_KEY *eckey=EC_KEY_new();
unsigned int sig_len;
sig_len = ECDSA_size(eckey);
ECDSA_SIG *signature;
signature = OPENSSL_malloc(sig_len);
    if (NULL == eckey)
    {
        printf("Failed to create new EC Key\n");
        function_status = -1;
    }
    else
    {
        EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (NULL == ecgroup)
        {
            printf("Failed to create new EC Group\n");
            function_status = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(eckey,ecgroup);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
                function_status = -1;
            }
           else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(eckey);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                    function_status = -1;
                }
                else
                {
                    signature = ECDSA_do_sign(hash, strlen(hash), eckey);
                    if (NULL == signature)
                    {
                        printf("Failed to generate EC Signature\n");
                        function_status = -1;
                    }
                }
            }
            //EC_GROUP_free(ecgroup);
        }
        //EC_KEY_free(eckey);
    }
addBlock(signature,eckey,filename1,ind);
clock_t toc = clock();

  
   
printf("Encoding time in %f seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC);
//OPENSSL_free(signature);
		//signature = NULL;

		/*EC_KEY_free(eckey);
		eckey = NULL;*/
fclose(file);
ind=ind+1;
// printf("hello");
break;
case 2:printf("verify which block");
scanf("%d",&n);
clock_t ticv = clock();
verifyBlock(n);
clock_t tocv = clock();

  
   
printf("Elapsed: %f seconds\n", (double)(tocv - ticv) / CLOCKS_PER_SEC);
break;
default:
          printf("wrong choice \n");
          break;
}
}
    return(0) ;
}

