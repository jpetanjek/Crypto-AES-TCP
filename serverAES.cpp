#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"

/* IPV4 makro konstanta navodi IPV4 adresu na koju se klijent povezuje */
#define IPV4 "127.0.0.1"
/* PORT makro navodi broj TCP porta na koji se klijent povezuje */
#define PORT "7252"
#define ERR 1;
#define OK 0;
#define VELICINA_REDA_CEKANJA 5

int main(int argc, char **argv) {

	byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];

	int izbor=0;
	std::string ciphertext;        
	std::string decryptedtext;
	int kljuc;
    char client_message[5000];
    
    int povratna; /* privremena varijabla za pohranu povratnih  vrijednosti funkcijskih poziva */
    int opisnik, opisnik_klijent; /* socket descriptor: jedan od servera i jedan koji predstavlja trenutno obradjivanog klijenta */
    struct addrinfo upute; /* struktura za parametriziranje getaddrinfo poziva (u engl. literaturi obicno 'hints') */
	struct addrinfo *rezultat; /* pokazivac na strukturu koja ce sadrzavati popunjene informacije o loopback adresi servera */
	struct sockaddr_storage adresa_klijent; /* struktura koja ce sadrzavati informacije o povezanom klijentu */
	socklen_t adresa_klijent_velicina; /* velicina strukture sockaddr_storage koja se popunjava pozivom accept() */

	std::cout<<"Unesite kljuc: ";std::cin>>kljuc;
    memset( key, kljuc, CryptoPP::AES::DEFAULT_KEYLENGTH ); //kljuè
    memset( iv, kljuc, CryptoPP::AES::BLOCKSIZE ); //inicijalni vektor

    /* dohvacanje strukture lokalne adrese */
    memset(&upute, 0, sizeof(struct addrinfo));
    upute.ai_family = AF_INET; /* koristi se IPv4 */
    upute.ai_socktype = SOCK_STREAM;
    povratna = getaddrinfo(IPV4, PORT, &upute, &rezultat);
    if(povratna != 0 ) {
        printf("getaddrinfo(): %s (%d)\n", gai_strerror(povratna), povratna);
        return ERR;
    }
    
    /* kreiranje opisnika prikljucnice (socket) */
    opisnik = socket(rezultat->ai_family, rezultat->ai_socktype, rezultat->ai_protocol);
    povratna = bind(opisnik, rezultat->ai_addr, rezultat->ai_addrlen);
    if(povratna == -1) {
        int brojgreske = errno;
            printf("bind(): %s (%d)\n", strerror(brojgreske), brojgreske);
            freeaddrinfo(rezultat);
            return ERR;
    }
	freeaddrinfo(rezultat);
    povratna = listen(opisnik, VELICINA_REDA_CEKANJA);
    if(povratna == -1) {
        int brojgreske = errno;
        printf("listen(): %s (%d)\n", strerror(brojgreske), brojgreske);
        return ERR;
    }

    puts("Krenula petlja");
    while(1) {
        adresa_klijent_velicina = sizeof adresa_klijent;
        opisnik_klijent = accept(opisnik, (struct sockaddr *)&adresa_klijent, &adresa_klijent_velicina);
        if(opisnik_klijent == -1) {
            int brojgreske = errno;
            printf("accept(): %s (%d)\n", strerror(brojgreske), brojgreske);
            return ERR;
        }

        printf("Povezao se klijent.\n");

		bzero(client_message,5000);
        read(opisnik_klijent, client_message, 5000);
	
		std::cout << std::endl <<"Enkriptirana poruka:"  << std::endl;

		for( int i = 0; i < strlen(client_message); i++ ) 
  		      std::cout << "0x" << std::hex << (0xFF & static_cast<byte>(client_message[i])) << " ";
        
		ciphertext = client_message;
		std::cout << std::endl << std::endl;

		CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH); //dekripcija
    	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv ); // postavljanje moda operacije CBC
    	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) ); //postavljanje dekriptora
    		
		stfDecryptor.Put( reinterpret_cast<const unsigned char*>(  ciphertext.c_str() ), ciphertext.size() );
   	 	stfDecryptor.MessageEnd();

		std::cout<<"Dekriptirana poruka: "<<decryptedtext<<std::endl;
        decryptedtext.clear();	
		ciphertext.clear();
		
        if(povratna == -1) {
            int brojgreske = errno;
            printf("send(): %s (%d)\n", strerror(brojgreske), brojgreske);
			return ERR;
        }

        close(opisnik_klijent);
        puts("Kraj veze...");
    }
    return OK;
}
//  g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o serverAES serverAES.cpp -lcryptopp
// ./serverAES
