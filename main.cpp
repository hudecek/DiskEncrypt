#include <iostream>
#include <assert.h>
#include <crypto++/sha.h>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <termios.h>
#include <unistd.h>


using namespace std;
using namespace CryptoPP;

void sha256sum(string data, byte* digest) {
    //string result = "";
    SHA256 sha;
    sha.CalculateDigest(digest, (byte*)data.c_str(), data.length());
}

/*
string AES256CBC(byte* key, byte* iv, string plaintext) {
    string ciphertext = "";
    CryptoPP::AES::Encryption encryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbc(encryption, iv);

    CryptoPP::StreamTransformationFilter transformationFilter(cbc, new CryptoPP::StringSink(ciphertext));
    transformationFilter.Put( reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length() + 1);
    transformationFilter.MessageEnd();
    return ciphertext;
}*/


string AES256CBCenc(byte* key, byte* iv, string plaintext) {
    string ciphertext = "";
    try {
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, iv);

        //add padding
        StringSource source(plaintext, true,
            new StreamTransformationFilter(e, new StringSink(ciphertext))
        );
    } catch (CryptoPP::Exception &e) {
        cerr << e.what() << endl;
        exit(1);
    }
    return ciphertext;
}

string AES256CBCdec(byte* key, byte* iv, string ciphertext) {
    string recovered = "";
    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, AES::MAX_KEYLENGTH, iv);

        //remove padding
        StringSource stream( ciphertext, true,
            new StreamTransformationFilter(d, new StringSink(recovered))
        );
    }
    catch( const CryptoPP::Exception& e )
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return recovered;
}

string bytesToString(string ciphertext) {
    string encoded;
    StringSource source(ciphertext, true,
        new HexEncoder(new StringSink(encoded))
    );
    return encoded;
}


int main()
{
    string password;
    string name;
    termios saveTerminal;
    byte help[SHA256::DIGESTSIZE];
    byte iv[AES::BLOCKSIZE];
    byte key[SHA256::DIGESTSIZE];

    tcgetattr(STDIN_FILENO, &saveTerminal);

    //keeping the old terminal to revert the printing ability
    termios alternedTerminal = saveTerminal;

    //stopping the terminal to echo input
    alternedTerminal.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &alternedTerminal);

    cout << "Enter name:" << endl;
    getline(cin, name);
    cout << "Enter password:" << endl;
    getline(cin, password);

    //reverting to printing input
    tcsetattr(STDIN_FILENO, TCSANOW, &saveTerminal);


    sha256sum(name, help);
    sha256sum(password, key);

    //using just first 128b of sha256sum for IV
    for(unsigned i = 0; i< AES::BLOCKSIZE; i++) {
        iv[i] = help[i];
    }


    /*
     * Encryption/decryption part
     */

    string ciphertext = "";
    string plaintext = "Hello";
    string encoded, recovered;


    ciphertext = AES256CBCenc(key, iv, plaintext);
    encoded = bytesToString(ciphertext);
    recovered = AES256CBCdec(key, iv, ciphertext);

    cout << "Ciphertext: " << encoded << endl;
    cout << "Recovered: " << recovered << endl;

    return 0;
}

