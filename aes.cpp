#include <iostream>
#include <iomanip>

#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"

using CryptoPP::AES;
using namespace std;

int main() {

    byte kljuc[ AES::DEFAULT_KEYLENGTH ], iv[ AES::BLOCKSIZE ];
    memset( kljuc, 0x00, AES::DEFAULT_KEYLENGTH ); //kljuè
    memset( iv, 0x00, AES::BLOCKSIZE ); //inicijalni vektor

    // Obicni tekst
	string obicnitekst="";
    cout<<"Unesi tekst za AES enkripciju i dekripciju: ";
	getline(cin,obicnitekst);
	cout << "Obicni tekst (" << obicnitekst.size() << " bytes): ";
	cout << obicnitekst;
	cout << endl << endl;

    // Kriptirani tekst
	string kriptiranitekst;
    AES::Encryption aesEncryption(kljuc, AES::DEFAULT_KEYLENGTH); //konkretna enkripcija
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv ); //cipher block chaining - mod operacije

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( kriptiranitekst ) ); //postavljanje enkriptora
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( obicnitekst.c_str() ), obicnitekst.length() + 1 );
    stfEncryptor.MessageEnd();

    cout << "Kriptirani tekst - hex (" << kriptiranitekst.size() << " bytes): ";
    for( int i = 0; i < kriptiranitekst.size(); i++ ) {
        cout << "0x" << hex << (0xFF & static_cast<byte>(kriptiranitekst[i])) << " ";
    }
    cout << endl << endl;

    // Dekriptirani tekst
	string dekriptiranitekst;
    AES::Decryption aesDecryption(kljuc, AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( dekriptiranitekst ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( kriptiranitekst.c_str() ), kriptiranitekst.size() );
    stfDecryptor.MessageEnd();

    cout << "Dekriptirani tekst: ";
    cout << dekriptiranitekst;
    cout << endl << endl;

    return 0;
}
//  g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o aesv2 aesv2.cpp -lcryptopp
// ./aesv2
