//
//  main.c
//  CertificateGenerator
//
//  Created by Roman Ligocki on 27/01/2020.
//  Copyright © 2020 Roman Ligocki. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "monocypher.h"

typedef struct mavlink_authority_certificate
{
   char certificateName[32];
   char owner[32];
   uint8_t public_key[32];
   uint8_t secret_key[32];
}mavlink_authority_certificate_t;

typedef struct mavlink_device_certificate
{
    uint8_t device_id;
    char device_name[20];
    char maintainer[20];
    uint8_t privileges;
    uint8_t public_key[32];
    uint8_t public_key_auth[32];
    uint8_t secret_key[32];
    uint8_t sign[64];
}mavlink_device_certificate_t;

int menu(void);
int authorityCertGen(void);
int deviceCertGen(void);
void signCertificate(mavlink_device_certificate_t *cert, uint8_t *sk, uint8_t *pk);
uint8_t checkCertificate(mavlink_device_certificate_t *cert, uint8_t *pk);
void cls(void);



int main(int argc, const char * argv[]) {
    
    int decision = 0;
    
    do{
        decision = menu();
    
        if(decision == 1){
            authorityCertGen();
        }
        
        if(decision == 2){
            deviceCertGen();
        }
    }while(decision != 3);
    
    return 0;
}

int menu(){
    
    int decision = 0;
    
    do{
        cls();
        printf("PX4 - Certificate generator 1.0 \n\n");
        
        printf("[1] Generate authority certificate \n");
        printf("[2] Generate device certificate \n");
        printf("[3] Exit generator \n\n");
        
        printf("Choose one option:");
        scanf("%d", &decision);
        getchar();
    }while(decision > 3 || decision < 1);
    
    return decision;
}

int authorityCertGen(void){
    
    mavlink_authority_certificate_t cert;
    
    cls();
    printf("-- Generation of authority certificate --\n");
    
    int rd = open("/dev/random", O_RDONLY);
    
    if (rd < 0)
     {
         printf("Problem with random generator\n");
         return 0;
     }
     else
     {
         ssize_t result = read(rd, cert.secret_key, sizeof cert.secret_key);
         if (result < 0)
         {
             printf("Problem with random generator\n");
             return 0;
         }
     }
    crypto_sign_public_key(cert.public_key, cert.secret_key);
    
    
    
    printf("Enter certificate name: ");
    scanf("%s", cert.certificateName);
    getchar();
    
    printf("Enter certificate owner: ");
    scanf("%s", cert.owner);
    getchar();
    
    printf("Name: %s \n", cert.certificateName);
    printf("Owner: %s \n", cert.owner);
    
    printf("Pubic_key:");
    for(int i = 0; i< 32; i++){
        printf("%d, ", cert.public_key[i]);
    }
    printf("\n");
    
    printf("Secret_key:");
    for(int i = 0; i< 32; i++){
        printf("%d, ", cert.secret_key[i]);
    }
    printf("\n");
    
    
    FILE *fp;
    fp = fopen("authority.cert", "wb");
    fwrite(&cert, sizeof(cert), 1, fp);
    fclose(fp);
    
    return 0;
}

int deviceCertGen(void){
    
    mavlink_authority_certificate_t authority_certificate;
    mavlink_device_certificate_t device_certificate;
    
    FILE *fp;
    fp = fopen("authority.cert", "rb");
    fread(&authority_certificate, sizeof(authority_certificate), 1, fp);
    fclose(fp);
    
    cls();
    printf("-- Loaded certificate --\n");
    printf("Name: %s\n", authority_certificate.certificateName);
    printf("Owner: %s\n", authority_certificate.owner);
    printf("Pubic_key:");
    for(int i = 0; i< 32; i++){
        printf("%d, ", authority_certificate.public_key[i]);
    }
    printf("\n");
    
    printf("Secret_key:");
    for(int i = 0; i< 32; i++){
        printf("%d, ", authority_certificate.secret_key[i]);
    }
    printf("\n");
    
    printf("-- Creation of device certificate --\n");
    
    int value = 0;
    printf("Enter device ID: ");
    scanf("%d", &value);
    getchar();
    device_certificate.device_id = value;
    
    printf("Enter device name [no white spaces]: ");
    scanf("%s", device_certificate.device_name);
    getchar();
    
    printf("Enter maintainer name [no white spaces]: ");
    scanf("%s", device_certificate.maintainer);
    getchar();
    
    printf("Enter privileges [0-255]: ");
    scanf("%d", &value);
    getchar();
    device_certificate.privileges = value;
    
    int rd = open("/dev/random", O_RDONLY);
    
    if (rd < 0){
         printf("Problem with random generator");
         return 0;
    }else{
         ssize_t result = read(rd, device_certificate.secret_key, sizeof device_certificate.secret_key);
         if (result < 0)
         {
             printf("Problem with random generator");
             return 0;
         }
    }
    crypto_key_exchange_public_key(device_certificate.public_key, device_certificate.secret_key);
    
    printf("Pubic_key:");
    for(int i = 0; i< 32; i++){
        printf("%d, ", device_certificate.public_key[i]);
    }
    printf("\n");
    
    printf("Secret_key:");
    for(int i = 0; i< 32; i++){
        printf("%d, ", device_certificate.secret_key[i]);
    }
    printf("\n");
    
    signCertificate(&device_certificate, authority_certificate.secret_key, authority_certificate.public_key);
    
    if(checkCertificate(&device_certificate, authority_certificate.public_key) == 0){
        printf("Certificate is valid");
    }
    
    memcpy(device_certificate.public_key_auth, authority_certificate.public_key, sizeof(authority_certificate.public_key));
    
    fp = fopen("device.cert", "wb");
    fwrite(&device_certificate, sizeof(device_certificate), 1, fp);
    fclose(fp);
    
    return 0;
}

void signCertificate(mavlink_device_certificate_t *cert, uint8_t *sk, uint8_t *pk) {

    uint8_t hash[64];
    crypto_blake2b_ctx ctx;
    
    uint8_t privileges[1];
    privileges[0] = cert->privileges;
    uint8_t device_id[1];
    device_id[0] = cert->device_id;
    
    crypto_blake2b_init(&ctx);
    crypto_blake2b_update(&ctx, (const uint8_t *)device_id, 1);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->device_name, 20);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->maintainer, 20);
    crypto_blake2b_update(&ctx, (const uint8_t *)privileges, 1);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->public_key, 32);
    crypto_blake2b_final(&ctx, hash);
    
    crypto_sign(cert->sign, sk, pk, hash, 64);
}

uint8_t checkCertificate(mavlink_device_certificate_t *cert, uint8_t *pk){
    
    uint8_t hash[64];
    crypto_blake2b_ctx ctx;
    
    uint8_t privileges[1];
    privileges[0] = cert->privileges;
    uint8_t device_id[1];
    device_id[0] = cert->device_id;
    
    crypto_blake2b_init(&ctx);
    crypto_blake2b_update(&ctx, (const uint8_t *)device_id, 1);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->device_name, 20);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->maintainer, 20);
    crypto_blake2b_update(&ctx, (const uint8_t *)privileges, 1);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->public_key, 32);
    crypto_blake2b_final(&ctx, hash);
    
    return crypto_check(cert->sign, pk, hash, 64);
}

void cls()
{
    system("@cls||clear");
}




