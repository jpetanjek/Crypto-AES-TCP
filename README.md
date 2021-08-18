# Crypto-AES-TCP
Simple server-client chat app with AES encryption and a TCP connection

Cryptography is one of the most commonly used types of computer security. Foundations
on the application of algorithms (so-called Ciphera and Deciphera) that convert the actual content of the message into
cyphertext, and with the help of appropriate private and / or public keys
restore the actual contents of the file. In this project work with the help of Crypto ++ libraries
we have implemented some of the cryptographic algorithms that have proven quite a bit throughout history
significant.
The application of the Crypto ++ library of classes of cryptographic algorithms and schemes represents very
a quality solution to problems that often occur in application implementations. Very large
The advantage of the Crypto ++ library is its availability, a wide range of diverse algorithms for
encryption and the fact that it is frequently updated due to its open-source properties (source code is
available to the public and updated by the Crypto ++ community). The library is free at
use and available on various operating systems (Windows, iOS, Linux ...) and is
compatible with a wide range of C ++ compilers. Since it's a library
intended for a programming language that is quite "close to the hardware" of the implementation
Cryptographic solutions will in many cases be faster than performance in
compared to solutions implemented in some other programming languages. We applied
library on AES, which is a symmetric cryptosystem, and symmetric cryptosystems require that
the sender and recipient know a common secret key. We further applied it to RSA which
falls under asymmetric crypto systems, the sender and receiver do not share the same secret key. Public
the key is used for encryption and is available to everyone. The private key is used to decrypt and
it is known only to the recipient.
Finally, when creating our example of a TCP server - client connection with AES encryption and
by decrypting messages, we learned a lot about dividing tasks, using different functions,
objects and classes from a library and we learned the most by studying the documentation itself and
explained on the Crypto ++ Wiki. The use of the library is hampered by compatibility issues.
