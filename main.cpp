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

int main()
{
    string password;
    string name;
    termios saveTerminal;
    byte iv[SHA256::DIGESTSIZE];
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


    sha256sum(name, iv);
    sha256sum(password, key);


    return 0;
}

