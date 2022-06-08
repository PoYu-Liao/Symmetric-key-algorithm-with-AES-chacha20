#include <cryptopp/chacha.h>
#include <cryptopp/secblock.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>

#include <iostream>
#include <string>
#include <fstream> 
#include <stdlib.h>
# include <ctime>
#include <filesystem>


using namespace std;
using namespace CryptoPP;
using namespace std::experimental::filesystem::v1;

ifstream inputfile;
ofstream outputfile;
ifstream in;
ofstream out;

void aes_cbc(string plain) {

	AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	//string plain = "CBC Mode Test";
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource ss(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
		
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print cipher text
	StringSource ss(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource

	cout << "cipher text: " << encoded << endl;
	

	/*********************************\
	\*********************************/
	
	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		cout << "recovered text: " << recovered << endl;
		inputfile.close();
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

}
void aes_cbcinfile(string filename) {


	//inputfile.open(filename, std::ios::binary);
	//ifstream in{ filename, std::ios::binary };
	in.open( filename, std::ios::binary );
	if (!in) {
		cout << "File not created!";
		return;
	}

	ofstream out{ "enc"+filename , std::ios::binary };
	AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	//string plain = "CBC Mode Test";
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		FileSource ensource{ in, true,
					   new CryptoPP::StreamTransformationFilter{
						   e, new CryptoPP::FileSink{out}}

		};
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	in.close();
	out.close();
	
	/*********************************\
	\*********************************/
	
	ifstream dein{ "enc"+filename  , std::ios::binary };
	ofstream deout{ "test-" + filename, std::ios::binary };
	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		FileSource desource{ dein, true,
					   new CryptoPP::StreamTransformationFilter{
						   d, new CryptoPP::FileSink{deout}}

		};

		inputfile.close();
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	dein.close();
	deout.close();

}

void aes_ctr(string plain) {

	AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	byte ctr[AES::BLOCKSIZE];
	prng.GenerateBlock(ctr, sizeof(ctr));

	//string plain = "CTR Mode Test";
	string cipher, encoded, recovered;

	
	try
	{
		cout << "plain text: " << plain << endl;

		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), ctr);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher. CTR does not.
		StringSource ss1(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
		
	}
	catch (CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}


	// Pretty print cipher text
	StringSource ss2(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	

	try
	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), ctr);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss3(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		

		cout << "recovered text: " << recovered << endl;
	}
	catch (CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}
void aes_ctrinfile(string filename) {

	
	ifstream in{ filename, std::ios::binary };
	if (!in) {
		cout << "File not created!";
		return;
	}
	ofstream out{ filename + "enc", std::ios::binary };

	AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	byte ctr[AES::BLOCKSIZE];
	prng.GenerateBlock(ctr, sizeof(ctr));

	//string plain = "CTR Mode Test";
	string cipher, encoded, recovered;


	try
	{
		
		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), ctr);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher. CTR does not.
		FileSource ensource{ in, true,
					   new CryptoPP::StreamTransformationFilter{
						   e, new CryptoPP::FileSink{out}}

		};
	}
	catch (CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	in.close();
	out.close();

	
	ifstream dein{ "enc" + filename  , std::ios::binary };
	ofstream deout{ "test-" + filename, std::ios::binary };


	try
	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), ctr);

		// The StreamTransformationFilter removes
		//  padding as required.
		FileSource desource{ dein, true,
					   new CryptoPP::StreamTransformationFilter{
						   d, new CryptoPP::FileSink{deout}}

		};

		
	}
	catch (CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	dein.close();
	deout.close();
}

inline bool EndOfFile(const FileSource& file)
{
	std::istream* stream = const_cast<FileSource&>(file).GetStream();
	return stream->eof();
}

void chacha20(string plain) {
	AutoSeededRandomPool prng;
	//std::string plain("My Plaintext!! My Dear plaintext!!"), cipher, recover;
	std::string cipher, recover;

	SecByteBlock key(32), iv(8);
	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());
	HexEncoder encoder(new FileSink(std::cout));

	std::cout << "Key: ";
	encoder.Put((const byte*)key.data(), key.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	std::cout << "IV: ";
	encoder.Put((const byte*)iv.data(), iv.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	// Encryption object
	ChaCha::Encryption enc;
	enc.SetKeyWithIV(key, key.size(), iv, iv.size());

	// Perform the encryption
	cipher.resize(plain.size());
	enc.ProcessData((byte*)&cipher[0], (const byte*)plain.data(), plain.size());

	std::cout << "Plain: " << plain << std::endl;

	std::cout << "Cipher: ";
	encoder.Put((const byte*)cipher.data(), cipher.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	ChaCha::Decryption dec;
	dec.SetKeyWithIV(key, key.size(), iv, iv.size());

	// Perform the decryption
	recover.resize(cipher.size());
	dec.ProcessData((byte*)&recover[0], (const byte*)cipher.data(), cipher.size());

	std::cout << "Recovered: " << recover << std::endl;

}
void chacha20infile(string filename) {



	ifstream in{ filename, std::ios::binary };
	if (!in) {
		cout << "File not created!";
		return;
	}
	ofstream out{ "enc"+filename , std::ios::binary };
	AutoSeededRandomPool prng;
	std::string cipher, recover;

	SecByteBlock key(32), iv(8);
	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());
	HexEncoder encoder(new FileSink(std::cout));

	std::cout << "Key: ";
	encoder.Put((const byte*)key.data(), key.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	std::cout << "IV: ";
	encoder.Put((const byte*)iv.data(), iv.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	// Encryption object
	// Perform the encryption
	try
	{
		ChaCha::Encryption enc;
		enc.SetKeyWithIV(key, key.size(), iv, iv.size());

		MeterFilter meter;
		StreamTransformationFilter filter(enc);
		
		FileSource source(in, false);
		FileSink sink(out);

		source.Attach(new Redirector(filter));
		filter.Attach(new Redirector(meter));
		meter.Attach(new Redirector(sink));
		const size_t BLOCK_SIZE = 4096;
		lword processed = 0;

		while (!EndOfFile(source) && !source.SourceExhausted())
		{
			source.Pump(BLOCK_SIZE);
			filter.Flush(false);

			processed += BLOCK_SIZE;

			
		}
		// Signal there is no more data to process.
		// The dtor's will do this automatically.
		filter.MessageEnd();
	}
	catch (const Exception& ex)
	{
		cerr << ex.what() << endl;
	}
	in.close();
	out.close();

	//cipher.resize(in.size());
	/*enc.ProcessData((byte*)&cipher[0], (const byte*)in.data(), in.size());
	FileSource ensourcebuchacha20{ in, true,
					   new CryptoPP::StreamTransformationFilter{
						   enc, new CryptoPP::FileSink{out}}

	};*/

	
	

	ifstream dein{ "enc" + filename  , std::ios::binary };
	ofstream deout{ "test-" + filename, std::ios::binary };

	// Perform the decryption
	try
	{
		ChaCha::Decryption dec;
		dec.SetKeyWithIV(key, key.size(), iv, iv.size());

		MeterFilter meter;
		StreamTransformationFilter filter(dec);
		ifstream dein{ "enc" + filename  , std::ios::binary };
		ofstream deout{ "test-" + filename, std::ios::binary };



		FileSource source(dein, false);
		FileSink sink(deout);

		source.Attach(new Redirector(filter));
		filter.Attach(new Redirector(meter));
		meter.Attach(new Redirector(sink));
		const size_t BLOCK_SIZE = 4096;
		lword processed = 0;

		while (!EndOfFile(source) && !source.SourceExhausted())
		{
			source.Pump(BLOCK_SIZE);
			filter.Flush(false);

			processed += BLOCK_SIZE;
						
		}
		// Signal there is no more data to process.
		// The dtor's will do this automatically.
		filter.MessageEnd();
	}


	catch (const Exception& ex)
	{
		cerr << ex.what() << endl;
	}
	/*FileSource ensourcebychacha20{ dein, true,
					   new CryptoPP::StreamTransformationFilter{
						   dec, new CryptoPP::FileSink{deout}}

	};*/
	dein.close();
	deout.close();

}

int main()
{
	char filename[55];
	int t, mod;
	clock_t Begin, End;


	cout << "加密file(1)或txt(2)...請輸入1或2:";
	cin >> t;
	
	if (t==1) {
		cout << "filename:";
		cin >> filename;
		Begin = clock();
		cout << "輸入數字選擇mode(1)AES-CBC(2)AES-CTR(3)chacha20: ";
		cin >> mod;
		
		switch (mod)
		{

		case 1:
			cout << "AES-CBC Mod\n";
			aes_cbcinfile(filename);
			break;

		case 2:
			cout << "AES-CTR Mod\n";
			aes_ctrinfile(filename);
			break;

		case 3:
			cout << "chacha20 Mod\n";
			chacha20infile(filename);
			break;

		default:
			cout << "錯誤mode!!";
			break;
		}
	}
	else if(t==2){
		cout << "filename:";
		cin >> filename;
		Begin = clock();
		char buffer[200] = { 0 };

		inputfile.open(filename, std::ios::in);
		inputfile.read(buffer, sizeof(buffer));
		string s(buffer);
		cout << "輸入數字選擇mode(1)AES-CBC(2)AES-CTR(3)chacha20: ";
		cin >> mod;
		switch (mod)
		{

		case 1:
			cout << "AES-CBC Mod\n";
			aes_cbc(s);
			break;
		
		case 2:
			cout << "AES-CTR Mod\n";
			aes_ctr(s);
			break;
		
		case 3:
			cout << "chacha20 Mod\n";
			chacha20(s);
			break;

		default:
			cout << "錯誤mode!!";
			break;
		}
		
	}
	else {
		cout << "錯誤指令!!";
		Begin = clock();
	}
	inputfile.close();
	outputfile.close();
	
	
	string filesizename(filename);
	
	auto size = std::experimental::filesystem::file_size(filesizename);
	
	cout << "file_size：" << size<< " bytes" << endl;
	
	End = clock();
	auto s = clock() / CLOCKS_PER_SEC;
	cout <<  "程式執行所花費：" << (double)clock() / CLOCKS_PER_SEC << " S" << endl;
	//cout <<  "程式進行運算所花費的時間：" << (double)(End - Begin) / CLOCKS_PER_SEC << " S" << endl;
	cout << "每秒可加密: "<< size / s <<" bytes/s" << endl;
	
	//filesize.close();
	/*if (!inputfile) {
		cout << "File not created!";
	}*/

	
	


	


	
	return 0;
}