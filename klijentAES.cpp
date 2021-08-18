#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"

/* IPV4 makro konstanta navodi IPV4 adresu na koju se klijent povezuje */
#define IPV4 "127.0.0.1"
/* PORT makro navodi broj TCP porta na koji se klijent povezuje */
#define PORT "7252"
/* maksimalna velicina poruke koju klijent moze prihvatiti od servera */
#define VELICINA 200

int main(int argc, char **argv){

	byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
	
	int kljuc, n;
	std::string plaintext;
	std::string ciphertext;
	
    int opisnik; /* socket descriptor klijenta */
    int procitano; /* broj procitanih okteta koje nam je server poslao */
	char medjuspremnik[VELICINA] = {'\0'}; /* medjuspremnik za pohranu poruke sa servera*/
	struct addrinfo upute; /* struktura za parametriziranje getaddrinfo poziva (u engl.*/
    struct addrinfo *rezultat; /* struktura koja ce sadrzavati popunjene informacije o */
	

	std::cout<<"Unesite kljuc: ";std::cin>>kljuc;
	std::cout<<"Unesite poruku: ";std::cin>>plaintext;

	memset( key, kljuc, CryptoPP::AES::DEFAULT_KEYLENGTH ); //kljuc
    memset( iv, kljuc, CryptoPP::AES::BLOCKSIZE ); //inicijalni vektor
        
	CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH); //priprema objekta za enkcipciju 
   	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv ); //postavljanje mod-a operacije CBC
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );

   	stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() + 1 );
    stfEncryptor.MessageEnd();

    n=ciphertext.length();

	std::cout<<"Velicina enkriptirane poruke u Bajtovima: "<<n;

   	char polje[n+1];
    strcpy(polje,ciphertext.c_str());

    /* dohvacanje adrese servera */
    memset(&upute, 0, sizeof(struct addrinfo));
    upute.ai_family = AF_INET;
    upute.ai_socktype = SOCK_STREAM;
    getaddrinfo(IPV4, PORT, &upute, &rezultat);

    /* kreiranje prikljucnice (socket-a) */
    opisnik = socket(rezultat->ai_family, rezultat->ai_socktype, rezultat->ai_protocol);

    /* povezivanje na server */
    connect(opisnik, rezultat->ai_addr, rezultat->ai_addrlen);
    if( send(opisnik , polje , strlen(polje) , 0) < 0) {
        puts("Slanje fail");
        return 1;
	}

    /* ucitavanje poruke sa servera u lokalni medjuspremnik */
    bzero(medjuspremnik,200);
    procitano = recv(opisnik, medjuspremnik, VELICINA, 0);

    if(procitano > 0 && procitano < VELICINA) {
        medjuspremnik[procitano] = '\0';
    }

    printf("%s\n", medjuspremnik);
	close(opisnik);

    return 0;
}
//  g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o klijentAES klijentAES.cpp -lcryptopp
// ./klijentAES
