#include <bits/stdc++.h>
#include <chrono>
using std::chrono::duration;
using std::chrono::duration_cast;
using std::chrono::high_resolution_clock;

using std::endl;
using std::wcerr;
using std::wcin;
using std::wcout;
#include <string>
using std::string;
using std::wstring;
#include <cstdlib>
using std::exit;
#include <assert.h>

// Cryptopp Library
#include "cryptopp/files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/filters.h"
using CryptoPP::Redirector; // string to bytes
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

// convert string
// Hex <-> Binary
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

// Base64 <-> Binary
#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

// Block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;
#include "cryptopp/aes.h"
using CryptoPP::AES;

// Mode of operations
#include "cryptopp/modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
#include "cryptopp/xts.h"
using CryptoPP::XTS;
#include "cryptopp/ccm.h"
using CryptoPP::CCM;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
// Ref: more here https://www.cryptopp.com/wiki/AEAD_Comparison
//  header part
#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <locale>
#include <cctype>
using namespace std;
using namespace CryptoPP;
const static int TAG_SIZE = 12;
CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];
CryptoPP::byte iv[DES::BLOCKSIZE];
CryptoPP::SecByteBlock keyXTS(0x00, CryptoPP::DES::DEFAULT_KEYLENGTH * 2); // 2 times DEFAULT_KEYLENGTH for XTS mode

void GenerateKeyAndIV(const string &keyformat, const string &keyFile, const string &ivFile, int keyLength)
{
	AutoSeededRandomPool prng;

	size_t keySize = DES::DEFAULT_KEYLENGTH;
	SecByteBlock key(keySize);
	SecByteBlock iv(DES::BLOCKSIZE);
	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());

	// Save key
	if (keyformat == "hex")
	{
		StringSource(key, key.size(), true,
					 new HexEncoder(
						 new FileSink(keyFile.c_str())));
		cout << "Key: ";
		StringSource(key, key.size(), true,
					 new HexEncoder(
						 new FileSink(cout)));
		cout << endl;
	}
	else if (keyformat == "bin")
	{
		StringSource(key, key.size(), true,
					 new FileSink(keyFile.c_str()));
		cout << "Key: ";
		StringSource(key, key.size(), true,
					 new HexEncoder(new FileSink(cout)));
		cout << endl;
	}
	else if (keyformat == "base64")
	{
		StringSource(key, key.size(), true,
					 new Base64Encoder(new FileSink(keyFile.c_str())));
		cout << "Key: ";
		StringSource(key, key.size(), true,
					 new HexEncoder(
						 new FileSink(cout)));
		cout << endl;
	}

	// Save IV
	if (keyformat == "hex")
	{
		StringSource(iv, iv.size(), true,
					 new HexEncoder(
						 new FileSink(ivFile.c_str())));
	}
	else if (keyformat == "bin")
	{
		StringSource(iv, iv.size(), true,
					 new FileSink(ivFile.c_str()));
	}
	else if (keyformat == "base64")
	{
		StringSource(iv, iv.size(), true,
					 new Base64Encoder(
						 new FileSink(ivFile.c_str())));
	}
	cout << "IV: ";
	StringSource(iv, iv.size(), true,
				 new HexEncoder(
					 new FileSink(cout)));
	cout << endl;
}

void PerformEncryption(const string &mode, const string &keyformat, const string &keyFile, const string &ivFile, const string &inputFile, const string &outputFile)
{
	// Load key, IV, and perform Encryption based on the specified mode, then save output...
	string plain;
	FileSource fs(inputFile.c_str(), true,
				  new StringSink(plain));
	string cipher;
	string encoded;
	encoded.clear();

	// LOAD KEY
	FileSource(keyFile.c_str(), true,
			   new CryptoPP::ArraySink(key, sizeof(key)), true); // FileSource
	encoded.clear();
	// LOAD IV
	FileSource(ivFile.c_str(), true,
			   new CryptoPP::ArraySink(iv, sizeof(iv)), true); // FileSource

	auto start = std::chrono::high_resolution_clock::now();

	for (int i = 0; i < 10000; i++)
	{
		cipher.clear();
		if (mode == "ECB")
		{
			ECB_Mode<DES>::Encryption e;
			e.SetKey(key, sizeof(key));
			StringSource s(plain, true,
						   new StreamTransformationFilter(e,
														  new StringSink(cipher)));
		}
		else if (mode == "CBC")
		{
			CBC_Mode<DES>::Encryption e;
			e.SetKeyWithIV(key, sizeof(key), iv);
			StringSource s(plain, true,
						   new StreamTransformationFilter(e,
														  new StringSink(cipher)));
		}
		else if (mode == "OFB")
		{
			OFB_Mode<DES>::Encryption e;
			e.SetKeyWithIV(key, sizeof(key), iv);
			StringSource s(plain, true,
						   new StreamTransformationFilter(e,
														  new StringSink(cipher)));
		}
		else if (mode == "CFB")
		{
			CFB_Mode<DES>::Encryption e;
			e.SetKeyWithIV(key, sizeof(key), iv);
			StringSource s(plain, true,
						   new StreamTransformationFilter(e,
														  new StringSink(cipher)));
		}
		else if (mode == "CTR")
		{
			CTR_Mode<DES>::Encryption e;
			e.SetKeyWithIV(key, sizeof(key), iv);
			StringSource s(plain, true,
						   new StreamTransformationFilter(e,
														  new StringSink(cipher)));
		}
		else
		{
			wcout << "Invalid mode\n";
			break;
		}
	}
	auto stop = std::chrono::high_resolution_clock::now();
	duration<double, std::milli> duration = (stop - start) / 10000.0;

	if (keyformat == "hex")
	{
		StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
		StringSource(cipher, true, new HexEncoder(new FileSink(outputFile.c_str())));
	}
	else if (keyformat == "bin")
	{
		StringSource(cipher, true, new StringSink(encoded));
		StringSource(cipher, true, new FileSink(outputFile.c_str()));
	}
	else if (keyformat == "base64")
	{
		StringSource(cipher, true, new Base64Encoder(new StringSink(encoded)));
		StringSource(cipher, true, new Base64Encoder(new FileSink(outputFile.c_str())));
	}
	else
	{
		wcout << "Invalid key format\n";
		exit(1);
	}
	//cout << "cipher text: " << endl;
	cout << "ciphertext was written to " << outputFile << endl;
	cout << fixed << setprecision(3) << "Average time: " << duration.count() << " ms" << endl;
}

void PerformDecryption(const string &mode, const string &keyformat, const string &keyFile, const string &ivFile, const string &inputFile, const string &outputFile)
{
	// Load key, IV, and perform decryption based on the specified mode, then save output...
	// 2 times DEFAULT_KEYLENGTH for XTS mode

	string cipher, recovered;
	string encoded;

	// LOAD KEY
	FileSource(keyFile.c_str(), true,
			   new CryptoPP::ArraySink(key, sizeof(key)), true);
	encoded.clear();
	FileSource(ivFile.c_str(), true,
			   new CryptoPP::ArraySink(iv, sizeof(iv)), true);
	encoded.clear();
	FileSource(inputFile.c_str(), true,
			   new StringSink(cipher), true);
	if (keyformat == "hex")
		StringSource(cipher, true,
					 new HexDecoder(
						 new StringSink(encoded)));
	else if (keyformat == "bin")
		StringSource(cipher, true,
					 new StringSink(encoded));
	else if (keyformat == "base64")
		StringSource(cipher, true,
					 new Base64Decoder(
						 new StringSink(encoded)));
	auto start = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < 10000; i++)
	{
		recovered.clear();
		if (mode == "ECB")
		{
			ECB_Mode<DES>::Decryption d;
			d.SetKey(key, sizeof(key));
			StringSource s(encoded, true,
						   new StreamTransformationFilter(d,
														  new StringSink(recovered)));
		}
		else if (mode == "CBC")
		{
			CBC_Mode<DES>::Decryption d;
			d.SetKeyWithIV(key, sizeof(key), iv);
			StringSource s(encoded, true,
						   new StreamTransformationFilter(d,
														  new StringSink(recovered)));
		}
		else if (mode == "OFB")
		{
			OFB_Mode<DES>::Decryption d;
			d.SetKeyWithIV(key, sizeof(key), iv);
			StringSource s(encoded, true,
						   new StreamTransformationFilter(d,
														  new StringSink(recovered)));
		}
		else if (mode == "CFB")
		{
			CFB_Mode<DES>::Decryption d;
			d.SetKeyWithIV(key, sizeof(key), iv);
			StringSource s(encoded, true,
						   new StreamTransformationFilter(d,
														  new StringSink(recovered)));
		}
		else if (mode == "CTR")
		{
			CTR_Mode<DES>::Decryption d;
			d.SetKeyWithIV(key, sizeof(key), iv);
			StringSource s(encoded, true,
						   new StreamTransformationFilter(d,
														  new StringSink(recovered)));
		}
		else
		{
			wcout << "Invalid mode\n";
			break;
		}
	}
	auto stop = std::chrono::high_resolution_clock::now();
	duration<double, std::milli> duration = (stop - start) / 10000.0;
	encoded.clear();
	// if (keyformat == "hex")
	// 	StringSource(recovered, true,
	// 				 new HexEncoder(
	// 					 new StringSink(encoded))); // HexEncoder
	// else if (keyformat == "bin")
	// 	StringSource(recovered, true,
	// 				 new StringSink(encoded));
	// else if (keyformat == "base64")
	// 	StringSource(recovered, true,
	// 				 new Base64Encoder(
	// 					 new StringSink(encoded)));
	// else
	// {
	// 	wcout << "Invalid key format\n";
	// 	exit(1);
	// }
	StringSource(recovered, true,
				 new FileSink(outputFile.c_str()));
	//cout << "Recovered text: " << recovered << endl;
	cout << "Recovered text was written to " << outputFile << endl;
	cout << fixed << setprecision(3) << "Average time: " << duration.count() << " ms" << endl;
}

int main(int argc, char *argv[])
{
	// Set locale to support UTF-8
#ifdef __linux__
	std::locale::global(std::locale("C.utf8"));
#endif

#ifdef _WIN32
	// Set console code page to UTF-8 on Windows
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);
#endif
	// Argument parser and handling...
	if (argc < 2)
	{

		cerr << "Usage:\n"
			 << argv[0] << " gen <key format> <keyFile> <ivFile>\n"
			 << argv[0] << " enc <mode> <key format> <keyFile> <ivFile> <plainFile> <cipherFile>\n"
			 << argv[0] << " dec <mode> <key format> <keyFile> <ivFile> <cipherFile> <plainFile>\n"
			 << "Mode: ECB, CBC, OFB, CFB, CTR.\n";
		exit(1);
	}
	string option = argv[1];

	if (option == "gen")
	{
		if (argc != 5)
		{
			cerr << "Usage: \n"
				 << argv[0] << " gen <key format> <keyFile> <ivFile>";
			exit(1);
		}
		string keyformat = argv[2];
		string keyFile = argv[3];
		string ivFile = argv[4];
		int keyLength = DES::DEFAULT_KEYLENGTH; // Fixed key length for DES
		GenerateKeyAndIV(keyformat, keyFile, ivFile, keyLength);
	}
	else if (option == "enc")
	{
		if (argc != 8)
		{
			cerr << "Usage: \n"
				 << argv[0] << " enc <mode> <key format> <keyFile> <ivFile> <plainFile> <cipherFile>";

			exit(1);
		}
		string mode = argv[2];
		string keyformat = argv[3];
		string keyFile = argv[4];
		string ivFile = argv[5];
		string inputFile = argv[6];
		string outputFile = argv[7];
		PerformEncryption(mode, keyformat, keyFile, ivFile, inputFile, outputFile);
	}
	else if (option == "dec")
	{
		if (argc != 8)
		{
			cerr << "Usage: "
				 << argv[0] << " dec <mode> <key format> <keyFile> <ivFile> <plainFile> <cipherFile>";
			exit(1);
		}
		string mode = argv[2];
		string keyformat = argv[3];
		string keyFile = argv[4];
		string ivFile = argv[5];
		string inputFile = argv[7];
		string outputFile = argv[6];
		PerformDecryption(mode, keyformat, keyFile, ivFile, inputFile, outputFile);
	}
	else
	{
		wcerr << "Invalid option\n";
		exit(1);
	}
	return 0;
}
