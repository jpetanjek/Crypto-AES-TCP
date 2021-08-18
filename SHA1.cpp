#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <iostream>
#include <string>

int main()
{
	CryptoPP::SHA256 hash;
	byte digest[CryptoPP::SHA256::DIGESTSIZE];
  
//unos poruke
	std::string message;
	std::cout << "Upisite poruku: ";
	std::getline(std::cin, message);

//virtual void HashTransformation::CalculateDigest(byte *digest, const byte *input, size_t length)
//Ažurira/izraèunava funkciju sažimanja od odreðenog input-a
	hash.CalculateDigest(digest,(const byte *)message.c_str(), message.size());

//transformacije buffer-a
	CryptoPP::HexEncoder encoder;
	std::string output;
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest,sizeof(digest));
	encoder.MessageEnd();

//ispis sažetka
	std::cout << "Rezultat: " << output << std::endl;
	return 0;
}
