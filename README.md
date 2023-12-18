# SecureChatApplication

## Description

This appliiation allows for encrypted chat communication between exactly 2 parties. The procedure for communication is outlined in
this document.

## Assumptions

- The handshake procedure used for mutual authentication makes use of RSA encryption, it is assumed that the client is aware of the server's public key and the server is aware of the client's public key.

- As the handshake uses public key cryptography, it is assumed that an adversary would be able to obtain the public key for either communicating party, however, the private keys are assumed to be secure, at least for the duration of the communication.

- The IP of the server is assumed to be known to the client, the server however does not know the source of the client's connection. Thus the client's identity must be established before any further communication is done.

## Claims

- Through the handshake procedure the server can be certain that the client is who they claim to be, and vice versa.

- Communication within a single session meet the requirements for perfect secrecy, as the session key is only known to the communicating parties.

- Stealing a single session key does not compromise any other session keys.

- Access to the server's private key, will allow an attacker to decrypt previous message, if they had previously recorded all messages, however, without access to all previous messages in addition to the private key, the attacker will not be able to decrypt any messages.

- An attacker who has access to a private key will not be able to overflow any of the used buffers, due to restrication on the size of the messages.

- An attacker will not be able to redirect messages to a different client, as the authentication procedure cannot be completed unless the party initiating communication is the same as the party that is completing it (see the handshake procedure).

## Handshake Procedure

1. The client initiates a connection to the server.
2. The client generates an AES session key (client key), and encrypts it using the server's public key.
3. The client sends the encrypted client key to the server.
4. The server decrypts the client key using its private key.
5. The server generates an AES session key (server key), and encrypts both it and the client key using the client's public key.
6. The server sends the encrypted client key and server key to the client.
7. The client decrypts the server key and client key using its private key.
8. The client confirms that the client key provided by the server is the same as the one it sent.
9. The client encrypts a the server key using the server's public key and sends it to the server.
10. The server decrypts the server key using its private key.
11. The server confirms that the server key provided by the client is the same as the one it sent.
12. The server and client now have shared keys that they can use to encrypt and decrypt messages.
13. When the server sends a message to the client, it encrypts it using the client key (An IV is generated for each message and send along side the message).
14. When the client sends a message to the server, it encrypts it using the server key (An IV is generated for each message and send along side the message).
15. The server and client can now communicate securely.

## Limitations

- The messages are missing a message signature, the code for message signing is present on another branch, however it was not completed in time for submission. This means an attacker could manipulate ciphertext, and the receiving party would not be able to detect it. However, the party recieving the affected message would not be able to decrypt it, as the message would be corrupted.
