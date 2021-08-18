#include <iostream>
#include <iomanip>
using namespace std;

#include <iomanip>
using std::hex;

#include <string>
using std::string;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

int main(int argc, char** argv)
{
	AutoSeededRandomPool psgb; //pseudo slucajan generiran broj

	// generiranje
	RSA::PrivateKey privKey; 
	privKey.GenerateRandomWithKeySize(psgb, 256); //generiraj privatni kljuc
	RSA::PublicKey pubKey(privKey); //generiraj javni kljuc

	cout << "modul: " << hex << privKey.GetModulus() << endl;
	cout << "privatni eksponent (d): " << hex << privKey.GetPrivateExponent() << endl;
	cout << "javni eksponent (e): " << hex << privKey.GetPublicExponent() << endl;
	cout << endl;

	////
	//n, e i d zadani
	//Integer n("0xbeaadb3d839f3b5f"), e("0x11"), d("0x21a5ae37b9959db9");

	//RSA::PrivateKey privKey;
	//privKey.Initialize(n, e, d);

	//RSA::PublicKey pubKey;
	//pubKey.Initialize(n, e);
	////

	string obicnitekst, dekriptiranitekst;
	Integer tr, er, dr;
	
	// Obicni tekst
	obicnitekst="";
    	cout<<"Unesi tekst za RSA enkripciju i dekripciju: ";
	getline(cin,obicnitekst);
	cout << "Obicni tekst (" << obicnitekst.size() << " bytes): ";
	cout << obicnitekst;
	cout << endl << endl;
	
	// obicnitekst -> big endian
	tr = Integer((const byte *)obicnitekst.data(), obicnitekst.size());
	cout << "tajna rijec (int): " << hex << tr << endl;

	// Enkripcija
	er = pubKey.ApplyFunction(tr);
	cout << "enkriptirana rijec (int): " << hex << er << endl;

	// Dekripcija
	dr = privKey.CalculateInverse(psgb, er);
	cout << "dekriptirana rijec (int): " << hex << dr << endl;

	// dekriptiranitekst - enkodiranje za ispis
	size_t req = dr.MinEncodedSize();
	dekriptiranitekst.resize(req);
	dr.Encode((byte *)dekriptiranitekst.data(), dekriptiranitekst.size());

	cout << "Dekriptirani tekst: " << dekriptiranitekst << endl;	

	return 0;
}
// g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o rsav2 rsav2.cpp -lcryptopp -lpthread
// ./rsav2
