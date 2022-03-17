# text-chat-system

Here you can find simple (text) chat system, but with a TLS layer: The TLS transport layer only accepts authentication with a client certificate.
Chat users can connect and then exchange messages, while direct connection will only be possible after confirming the availability of both clients. 

Due to the specificity of the text chat (no pressure on the time of message delivery, all messages must be delivered in the right order), client-client communication will be carried out using the TCP protocol.
In the case of client-server communication, a secure connection channel will be established and a private key and certificate will be created.
Three keys are used to initiate a contact and an SSL connection: session, public and private.
Connecting to the server is done by sending the first notification from the client.
In network communication, users are identified by a socket which is a combination of an IP address and a port address.
As part of the project, it will be possible to handle several sessions at the same time.
The server listens for incoming client connections all the time, if a new client connects, it will be added to the collection of server sockets. For each connected client, a new thread will be started that listens for incoming messages sent from the client and broadcasts them to the recipient.
The client script is run by the user, so the same code will be run by a different user, but each will have a separate socket, so they will have their own unique communication channel.
The moment a client tries to access a server already secured with SSL, they establish SSL contact with each other.
After running the script, the client creates a unique client socket and, after sending the notification, connects to the server, listens for messages coming from the server and prints them on the console, and waits for the client to enter the message to be sent to the server.
The commands supported by the server are displayed in the terminal.

SSL operation scheme:
1. The client establishes a connection with the server secured with an SSL certificate
2. The server sends a copy of the SSL certificate
3. The client verifies the SSL certificate and checks that the certificate is valid and valid
If the certificate is trusted, the client sends back the symmetric session key using the public key
4. The server decrypts the session key with the private key and sends back the confirmation, and then starts the encrypted session
5. The client and server send data to each other using the session key 
