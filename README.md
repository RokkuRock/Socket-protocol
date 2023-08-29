# Socket Protocol

A socket-network library with MIT-license, containing simple practices across Linux and windows platforms, including **Windows 10**, and linux **ubuntu** distro. All of the practices are written in pure C library providing server-client data transmission, with features such as **Log data formatting**, data parsing, and log data minitoring and data transmission.

# UDP
- Standard Library Practices for server-client data transmission
  - Linux Ubuntu [22.04.2 LTS]
  - Microsoft Windows [10.0.19045.3086]
- User Instruction:
  1. Change Client.c, server.c port and IP setting (linux)
    - Client.c code: 
      ```c
      int main() {

          char *ip = "140.92.164.91"; // Change this to your ip address using ip a in linux terminal

          int port = 7000; // make sure to open this port or change to other available ports, using ufw status in linux terminal to inspect available ports.
            // if no available ports, execute command "sudo ufw allow [portnumber, ex:7000]
          ......and many more default code content......
      }```
    - server.c code:
      ```c
      int main(int argc, char **argv){

          if (argc != 2) {

          printf("Usage: %s <port>\n", argv[0]);

          exit(0);
          }
          char *ip = "140.92.164.91"; // Change this to your hosting server ip address

          int port = atoi(argv[1]);
      }```
  2. Compile server/client using gcc:
    ```bash
    gcc server.c -o server   
    gcc client.c -o client
    ```
  3. Execute and host server on targeting IP and port number:
    ```bash
    ./server 127.0.0.1 7000
    ```
  4. Execute connecting client on targeting server IP with another terminal:
    ```bash
    ./client []
    ```
    - Execution result should be shown like this:
    ```bash  
    [+]Data recv: Call from client 1!
    [+]Data send: Transmission sucessful. You are using UDP server.  
    ```
  5. End server and client program with ctrl+c command

# LibuvTCP 
- Simple server-client Log data transmission practice without solely using open-source libuv library without other dependencies.
- Ubuntu Server / Client
  - Linux Ubuntu [22.04.2 LTS]
  - Microsoft Windows [10.0.19045.3086]
- bigClient.c: client with packet transfer testing per milisecond, sample code using libuv library, asynchronous packet-sending structure
- client.c: client side example code using libuv, asynchronous packet-sending structure
- singleThreadedServer.c: server side example code using libuv, asynchronous packet writer using default single-threaded transmission
- multithreadedServer.c: server side example code using libuv, asynchronous packet writer using thread-manager struct and multi-threaded transmission
- User Instruction using multithreadedServer.c and bigClient.c as example:
  1. Check and revise Log data storage directory in single/multi-threadedServer.c:
    ```c
    void process_xml_and_write(const char *xml_data, size_t xml_data_len) {
    static int file_number = 1;
    char filename[100];
    
    uv_mutex_lock(&file_mutex); // Use mutex_lock to lock the accessibility during processing xml

    snprintf(filename, sizeof(filename), "/home/vboxuser/Projects/TCP/output/output%d.xml", file_number++);
    
    // Create the output directory if it doesn't exist
    struct stat st = {0};
    if (stat("/home/vboxuser/Projects/TCP/output", &st) == -1) {    Change the directory path of stat"/home...output" according to your desired path
        mkdir("/home/vboxuser/Projects/TCP/output", 0700);          Change the path to the same as stat "/" you specify
    }
    }......rest of the code remain the same......
    ```
  2. Compile server and client using gcc or vscode(refer to building environment session for more setting details):
    ```bash
    gcc multithreadedServer.c -o multithreadedServer -luv 
    gcc bigClient.c -o bigClient -luv
    ```
  3. Execute Server and Client, below is sample result:
    ```bash
    ./multithreadedServer
        dummy callback
        dummy callback
        dummy callback
        Server listening on port 7000...
    ./bigClient
      Client connected to server 127.0.0.1:7000
    ```
    - Server side terminal result:
    ```bash
        dummy callback
        Received call from client: <xml>Some XML data goes here.</xml>
        Log file /home/vboxuser/Projects/TCP/output/output1.xml transmission completed!
        Received call from client: <xml>Some XML data goes here.</xml>
    ```
  4. End bigClient.c program with ctrl+c to stop transfering log string, server will be back in listening state 
  5. End server.c program with ctrl+c to terminate program

# libuvWinTCP
- Window 10 version of libuv TCP practice, but only practice with client, no windows server available.
- Can be used to transfer data with linux ubuntu server code in this repository, cross-platform available
- User instruction when using winClient.c:
  ```bash
  gcc multithreadedServer.c -o multihreadedServer -luv (can be replaced with singleThreaded if wanted)
  gcc winClient.c -o winClient -luv
  ```
- Execution result:
  ```bash
  Client: Client connected to server 140.92.164.91:7000
    Server: New connection established
    Received call from client: <Event><EventID>12345</EventID><Source>Application</Source><Message>Sample event log message</Message></Event>
    Log file /home/vboxuser/Projects/TCP/output/output1.xml transmission completed!
  ```
# images
  - Highlighted photos during early-stage testing using socket standard library, for reference
 
# LogDigestLibuv_linux
- DigestMain.c
  - Original API testing for logdigest API, monitoring multi.log file content specified in ld_watch_multilog path
  - Three Log formats are supported, including syslog, multilog, and windows_event_logs callbacks can be added for testing in the int main()
- LogParseServer.c
  - Host for receiving multiple log strings, and use I/O to write and save strings as log data in xml format
  - Generate xml file according to current timestamp and saved to targeted directory
- DigestClient.c
  - Recognize multilog log format
  - Monitoring multi.log file changes using logDigest API, polling log data in specified ld_watcher directory
- LogDigest API Integration
  - Integrate Ubuntu client code and LogDigest API to complete log data monitoring, parsing, trasmission and log generation
  - Support Common Log formats, including syslog, multilog, and windows_event_logs structured log data
- User Instruction for digesting process between server.c and client.c
  - Change the socket configuration of LogParserServer.c to fit your hosting environment:
    ```c
      #define DEFAULT_PORT 7000
      #define DEFAULT_BACKLOG 128 // Change this to allow pending connections during multiple log data transmission
      #define MAX_FILENAME_LEN 100 
      #define FILENAME_PREFIX "/home/vboxuser/Projects/LogDigestLibuv_linux/output" // Change this to your desired log data file saving path after transmission
    ```
  - Change the socket configuration of DigestClient.c to fit your environment:
    ```c  
      #define DEFAULT_PORT 7000
      #define DEFAULT_IP "127.0.0.1" // Change this to your server IP if needed
      #define SEND_INTERVAL_MS 1000  // Adjust the interval as needed, 1000 milisecond per 1 xml writing for default
    ```
  - Change the targeted listening path for DigestClient.c
    ```c
    - ld_watch_multilog("/home/vboxuser/Projects/LogDigestLibuv_linux/multiLogCollector/multi.log"); //Change the " " path to your multi.log file path
    ```bash
  - Executing server-client transmission:
    gcc LogParseServer.c -o LogParserServer -luv
    gcc DigestClient.c logdigest.c -o DigestClient -luv
    ./LogParserServer 
      Server listening on port 7000...
    ./DigestClient 
      Client connected to server 127.0.0.1:7000
    ```
    - Go to your multilog directory, open multi.log file using notepad or vscode or any text editor
      - Sample log file content:
        - @400000003b4a39c2cafebabe   fatal: message\twith\ttabs
          @400000003b4a39c2cafebabe   fatal: message\twith\ttabs
          @400000003b4a39c2cafebabe   some message with spaces
          @400000003b4a39c2cafebabe   coolmsg
          @400000003b4a39c2cafebabe some msg
          @400000003b4a39c2cafeffff asdfasdfasdf
          @400000003b4a39c2cff asdfasdfasdf
          @400000003b4a39c2cff asdfasdfasdf
          @400000003b4a39c2cff ads
          @400000033d9a6b282f3dab78 bad request 
      - Press ctrl+S to load the current cotent log data, transmission result should be shown:
        ```bash
        Received call from client: /home/vboxuser/Projects/LogDigestLibuv_linux/multiLogCollector/multi.log - @400000003b4a39c2cafebabe - fatal: message\twith\ttabs/ home/vboxuser/Projects/LogDigestLibuv_linux/multiLogCollector/multi.log - @400000003b4a39c2cafebabe - fatal: message\twith\ttabs/home/vboxuser/Projects/LogDigestLibuv_linux/multiLogCollector/multi.log - @400000003b4a39c2cafebabe - some message with spaces/home/vboxuser/Projects/LogDigestLibuv_linux/multiLogCollector/multi.log - @400000003b4a39c2cafebabe - coolmsg/home/vboxuser/Projects/LogDigestLibuv_linux/multiLogCollector/multi.log - @400000003b4a39c2cafebabe - some msg/home/vboxuser/Projects/LogDigestLibuv_linux/multiLogCollector/multi.log - @400000003b4a39c2cafeffff - asdfasdfasdf/home/vboxuser/Projects/LogDigestLibuv_linux/multiLogCollector/multi.log - @400000033d9a6b282f3dab78 - bad request 
        Log file /home/vboxuser/Projects/LogDigestLibuv_linux/output/output2023-08-29.xml transmission completed!
        ```
    - Add "@4000000783c049d55a7439ee Service disabled" this to the bottom line of code, make sure the format is correct (" "spacing, @ symbol should be same as above)
    - When finished editing, press ctrl+S to save the file, updated transmission result should be shown:
      ```bash
      - Log file /home/vboxuser/Projects/LogDigestLibuv_linux/output/output2023-08-29.xml transmission completed!
        No client message received in one minute. Sleeping...
        No client message received in one minute. Sleeping...
        No client message received in one minute. Sleeping...
        Received call from client: /home/vboxuser/Projects/LogDigestLibuv_linux/multiLogCollector/multi.log - @4000000783c049d55a7439ee - Service disabled
        Log file /home/vboxuser/Projects/LogDigestLibuv_linux/output/output2023-08-29.xml transmission completed!
      ```
    - To check the log transmission into file, you can check the path of your /output you specified, there should be saved .xml format log file according to timestamp:
      - example name of file should be like this: output2023-08-29.xml

# cJSONLogDIgest_linux Building Environment:
1. Using vcpkg (windows 10)for library management for include path, bin (uv.dll), include (uv, uv.h) , lib (uv.lib,) 
2. Include "logdigest.h", "cJSON.h" in your working directory
3. gcc compile with "logdigest.c", "cJSON.c", "-luv",
4. Sample "arg" for windows 10 environment (task.json)
  ```json
  "args": [
				"-g",
                "${file}",
                "-o",
                "${fileDirname}\\${fileBasenameNoExtension}.exe",
                "-I",
                "C:\\vcpkg\\installed\\x64-windows\\include",
                "-L",
                "C:\\vcpkg\\installed\\x64-windows\\lib",
                "-luv",
                "-lws2_32",
                "-liphlpapi",
                "-luserenv",
    ],
  ```
- Sample "arg" for linux ubuntu building environment (task.json)
  ```json
  "args": [
				"-fdiagnostics-color=always",
				"-g",
				"${file}",
				"-o",
				"${fileDirname}/${fileBasenameNoExtension}",
				"-luv",
				"logdigest.c",
				"cJSON.c",
			], 
  ```

# cJSONLogDigest_linux
- New features of dynamic changing IP setting of DigestCLient.c
- Chagne IP, port numbers without compiling, using cJSON library
- User Instruction of using cJSON Library and program execution
  - Change configuration of DigestClient.c:
    ```c
    - const char *json_filename = "/home/vboxuser/Projects/AutoLogDigest_linux/serverConfig/serverConfig.json"; //Change the serverConfig.json Monitoring path
  - Change ld_watch_multilog path to monitor multi.log file changes
    -  ld_watch_multilog("/home/vboxuser/Projects/cJSONLogDigest_linux/multiLogCollector/multi.log"); // change the " " path to your location of saving multi.log
    ```
  - Change the serverConfig.json content to fit your environment:
    ```json
    - { "IP": "127.0.0.1", "Port": 7000 } // change the value of "IP" and "Port" numbers to fit your network environment
    ```
  - Start executing LogParser and DigestClient:
    ```bash
    gcc LogParseServer.c -o LogParseServer -luv
    gcc DigestClient.c logdigest.c cJSON.c -o DigestClient -luv
    ./LogParseServer
      Server listening on port 7000...
    ./DigestClient 
      Client connected to server 140.92.164.91:7000
    ```  
    - Ctrl+S on multi.log file
      - Server terminal:
        ```bash
        New connection established
        Received call from client: /home/vboxuser/Projects/cJSONLogDigest_linux/multiLogCollector/multi.log - @400000003b4a39c2cafebabe - fatal: message\twith\ttab
        Log file /home/vboxuser/Projects/LogDigestLibuv_linux/output/output2023-08-29.xml transmission completed!
        ```
    - Check your /path/to/output to find newly generated .xml log file, sample output log file name: output2023-08-29

# sslAuthServer (Beta)
- Basic scanf username/password login feature available
- Certificate and private Key authentication is not finished yet, to be developed
- Building Environment (vscode):
  ```json
  - "args": [
				"-fdiagnostics-color=always",
				"-g",
				"${file}",
				"-o",
				"${fileDirname}/${fileBasenameNoExtension}",
				"-lssl",
				"-lcrypto",
			],
  ```      
- User Instruction for basic scanf login feature:
  - Change the IP/port number macro to fit your network environment:
    ```c
    #define SERVER_IP "127.0.0.1"
    #define SERVER_PORT 8081
    ```
  - Generate key, certificate and signing certificate before executing program
    ```bash
    cd myCertPem (if it doesn't exist, create a folder named myCertPem in your project directory)
    openssl genpkey -algorithm RSA -out server.key
    ..+......+.+......+.....+....+..............+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*...+.....+.......+...........+....+......+..+.+......+.....+.+.........+.....+...+.......+......and more encryped message
    openssl req -new -key server.key -out server.csr
    ```
    - Certificate configuration:
      ```bash
      Country Name (2 letter code) [AU]:TW
      State or Province Name (full name) [Some-State]:
      Locality Name (eg, city) []:
      Organization Name (eg, company) [Internet Widgits Pty Ltd]:
      Organizational Unit Name (eg, section) []:
      Common Name (e.g. server FQDN or YOUR name) []:
      Email Address []:
      // Most of the settings above can be left blank
      Please enter the following 'extra' attributes
      to be sent with your certificate request
      A challenge password []:1234  // enter any value of at least 4 bytes
      An optional company name []:  // can be left balnk
      ```
    - Signing Certificate with key:
      ```bash
      openssl x509 -req -in server.csr -signkey server.key -out server.crt
        Certificate request self-signature ok
        subject=C = TW, ST = Some-State, O = Internet Widgits Pty Ltd
      ```
    - In myCertPem folder, you will see three files, including server.key, server.csr, server.crt
      - Change server.key file name to private_key.key, and server.crt to certificate.crt
      - If you want to customize your own name, you can change this part of code to monitor different path and file name:
        ```c
        - // Define file directory
          #define CERTIFICATE_FILE "/home/vboxuser/Projects/sslAuthServer/myCertPem/certificate.crt" // change the path of certificate"" here if wanted
          #define PRIVATE_KEY_FILE "/home/vboxuser/Projects/sslAuthServer/myPrivatekey/private_key.key" // change the path of private key "" here if wanted
        ```  
  - Continue executing commands in terminal to start the scanf login authentication program
    ```bash
    cd .. 
    gcc sslServer.c -o sslServer -lssl -lcrypto
    gcc sslClient.c -o sslClient -lssl -lcrypto
    sudo ./sslServer 8081
    ./sslClient 127.0.0.1 8081
    Enter the User Name : 
    ```
    // server side for the present:
    ```bash 
    Connection: 127.0.0.1:40026
    No certificates.
    ```
    // client side to be processed with user input 
    ```bash
    Enter the User Name : aticle
    Enter the Password : 123
    ```
  - Client execution result:
    ```bash
    Connected with TLS_AES_256_GCM_SHA384 encryption

    Server certificates:

    Subject: /C=TW/ST=Some-State/O=Internet Widgits Pty Ltd

    Issuer: /C=TW/ST=Some-State/O=Internet Widgits Pty Ltd

    Received: "<\Body>                               <Name>aticleworld.com</Name>                 <year>1.5</year>                 <BlogType>Embedede and c\c++<\BlogType>                 <Author>amlendra<Author>                 <\Body>"
    ```
  - Server execution result:
    ```bash
    Client msg: "<Body>                               <UserName>aticle<UserName>                 <Password>123<Password>                 <\Body>"
    ```
  - If you want to change the login User name or Password, you can modify code in sslServer:
    ```c
        - void Servlet(SSL* ssl) /* Serve the connection -- threadable */
    {
        char buf[1024] = {0};
        int sd, bytes;
        const char* ServerResponse="<\\Body>\
                                  <Name>aticleworld.com</Name>\
                    <year>1.5</year>\
                    <BlogType>Embedede and c\\c++<\\BlogType>\
                    <Author>amlendra<Author>\
                    <\\Body>";
        const char *cpValidMessage = "<Body>\
                                  <UserName>aticle<UserName>\
                    <Password>123<Password>\
                    <\\Body>";
                    // ...and many more source code in sslServer.c...
    }
    ```








