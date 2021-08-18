#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <iostream>
#include <string>

int main()
{
	CryptoPP::SHA256 hash;
	byte digest[CryptoPP::SHA256::DIGESTSIZE];
	std::string username, password, salt, output;
  
////unos
	std::cout << "Unesite korisnicko ime: ";
	std::getline(std::cin, username);
	std::cout << std::endl << "Unesite lozinku: ";
	std::getline(std::cin, password);
	salt = username + password;

//Ažurira/izraèunava funkciju sažimanja od odreðenog input-a
	hash.CalculateDigest(digest,(const byte *)salt.c_str(),salt.size());

//transformacije buffer-a
	CryptoPP::HexEncoder encoder;
	CryptoPP::StringSink *SS = new CryptoPP::StringSink(output);
	encoder.Attach(SS);
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();

//ispis
	std::cout << "Rezultat: " << output << std::endl;
	return 0;
}
