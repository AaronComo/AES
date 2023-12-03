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


## Performance
~~~c++
Plain Text:	0001000101a198afda78173486153566
Key:		00012001710198aeda79171460153594
Encoded:	6cdd596b8f5642cbd23b47981a65422a
Decoded:	0001000101a198afda78173486153566

Testing Performance...
100000 rounds:          1.402	seconds
Encryptions per second: 71326	rounds
~~~
Run on MacBook Air with Apple M2 chip and 16GB RAM.
