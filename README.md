# AES

## Usage

There are two available APIs: `.encode()` and `.decode()`.

~~~c++
int main(int argc, char *argv[]) {
    AES128 aes = AES128();
    string M = "0001000101a198afda78173486153566";
    string K = "00012001710198aeda79171460153594";
    string C = aes.encode(M, K);
    string decoded = aes.decode(C, K);
}
~~~



## Note

Inputs and keys should be hex strings.
