# PyChat

PyChat implements a chat system composed of:
* a Client application: it will interface with other user/clients and it allows them to send and receive messages.
* a Server application: it is used from  the clients to setup the communication 

# The Client

The client application:
* perform send and reccive message
* two client exchange the messages one eache other in peer-to-peer by UDP connnection
* Each client is run by the command:
`python Client.py <Nickname> <IP-address> <port>`
* The IP address and port are the interfaces where the client receives the message from othe clients.
eg. `python chat_client foo 127.0.0.1 2001`
* provide a textual interface where the commands could be run to perform specific operation.
    * !help --> show the commands available
    * !connect user --> start a new chat with the specific user
    * !usersList --> get the list of user in the server
    * !disconnect --> free the client from the current chant
    * !quit --> to close appplication

# The Server

* In order to get IP addresses and port by the nickname each clients get contact with the Server
• The server application can be run by the command:
`python Server.py <IP address> <port>`
     the IP address and port specified is where the server is in listening to get the message from client. 
eg: `python chat_server 127.0.0.1 3000`

# Usecases

![/img/pdf_512x512.png](usecases/usecase_diagram.pdf)

