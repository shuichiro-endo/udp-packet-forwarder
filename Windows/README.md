# udp packet forwarder (Windows)

udp packet forwarder (ipv4, ipv6)

## Installation
### Install dependencies
- openssl
    1. download [openssl 3.0 version](https://www.openssl.org/source/)
    2. extract openssl-3.0.x.tar.gz
    3. install openssl. see openssl-3.0.x\NOTES-WINDOWS.md (Quick start)
- visual studio community (Desktop development with C++)
    1. install Desktop development with C++

Note: It takes a lot of time to install these.

### Install
1. download files
```
git clone https://github.com/shuichiro-endo/udp-packet-forwarder.git
```
2. run x64 Native Tools Command Prompt for VS 2022
3. set environment variable
```
set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
set LIB=%LIB%;C:\Program Files\OpenSSL\lib
set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib
```
4. build
    - server
    ```
    cd udp-packet-forwarder\Windows\server
    compile.bat
    ```
    - client
    ```
    cd udp-packet-forwarder\Windows\client
    compile.bat
    ```
5. copy openssl dll files (libcrypto-3-x64.dll, libssl-3-x64.dll) to the client and server directory
    - server
    ```
    cd udp-packet-forwarder\Windows\server
    copy "C:\Program Files\OpenSSL\bin\libcrypto-3-x64.dll" .
    copy "C:\Program Files\OpenSSL\bin\libssl-3-x64.dll" .
    ```
    - client
    ```
    cd udp-packet-forwarder\Windows\client
    copy "C:\Program Files\OpenSSL\bin\libcrypto-3-x64.dll" .
    copy "C:\Program Files\OpenSSL\bin\libssl-3-x64.dll" .
    ```

## Usage
- server
```
Normal mode  : client -> server
usage        : server.exe -h local_server_ip(tcp) -p local_server_port(tcp) -H bind_ip(udp) -P bind_port(udp) -a target_ip(udp) -b target_port(udp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]
example      : server.exe -h 0.0.0.0 -p 9000 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53
             : server.exe -h 0.0.0.0 -p 9000 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s
             : server.exe -h 0.0.0.0 -p 9000 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s -t 300 -u 0
             : server.exe -h :: -p 9000 -H ::1 -P 60000 -a ::1 -b 10053
             : server.exe -h fe80::xxxx:xxxx:xxxx:xxxx%10 -p 9000 -H fe80::xxxx:xxxx:xxxx:xxxx%10 -P 60000 -a fe80::xxxx:xxxx:xxxx:xxxx%10 -b 10053 -s
             : server.exe -h 0.0.0.0 -p 9000 -H 2001:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx -P 60000 -a 2001:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx -b 53 -s
or
Reverse mode : client <- server
usage        : server.exe -r -h client_ip(tcp) -p client_port(tcp) -H bind_ip(udp) -P bind_port(udp) -a target_ip(udp) -b target_port(udp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]
example      : server.exe -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53
             : server.exe -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s
             : server.exe -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s -t 300 -u 0
             : server.exe -r -h ::1 -p 1234 -H ::1 -P 60000 -a ::1 -b 10053
             : server.exe -r -h fe80::xxxx:xxxx:xxxx:xxxx%10 -p 1234 -H fe80::xxxx:xxxx:xxxx:xxxx%10 -P 60000 -a fe80::xxxx:xxxx:xxxx:xxxx%10 -b 10053 -s
             : server.exe -r -h 192.168.0.5 -p 1234 -H 2001:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx -P 60000 -a 2001:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx -b 53 -s
```

- client
```
Normal mode  : client -> server
usage        : client.exe -h local_server_ip(udp) -p local_server_port(udp) -H remote_server_ip(tcp) -P remote_server_port(tcp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]
example      : client.exe -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000
             : client.exe -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000 -s
             : client.exe -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000 -s -t 300 -u 0
             : client.exe -h :: -p 5000 -H ::1 -P 9000
             : client.exe -h fe80::xxxx:xxxx:xxxx:xxxx%10 -p 5000 -H fe80::xxxx:xxxx:xxxx:xxxx%10 -P 9000 -s
             : client.exe -h fe80::xxxx:xxxx:xxxx:xxxx%10 -p 5000 -H 192.168.1.10 -P 9000 -s
or
Reverse mode : client <- server
usage        : client.exe -r local_server_ip(udp) -p local_server_port(udp) -H local_server2_ip(tcp) -P local_server2_port(tcp) [-s (tls)] [-t forwarder tv_sec(timeout 0-3600 sec)] [-u forwarder tv_usec(timeout 0-1000000 microsec)]
example      : client.exe -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234
             : client.exe -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234 -s
             : client.exe -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234 -s -t 300 -u 0
             : client.exe -r -h :: -p 5000 -H :: -P 1234
             : client.exe -r -h fe80::xxxx:xxxx:xxxx:xxxx%10 -p 5000 -H fe80::xxxx:xxxx:xxxx:xxxx%10 -P 1234 -s
             : client.exe -r -h fe80::xxxx:xxxx:xxxx:xxxx%10 -p 5000 -H 0.0.0.0 -P 1234 -s
```

### Normal mode (client -> server)
1. run my server
```
# no TLS
server.exe -h 0.0.0.0 -p 9000 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53

# TLS
server.exe -h 0.0.0.0 -p 9000 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s
```
2. run my client
```
# no TLS
client.exe -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000

# TLS
client.exe -h 0.0.0.0 -p 5000 -H 192.168.1.10 -P 9000 -s
```
3. connect to my client from other udp clients
```
dig @127.0.0.1 -p 5000 google.com +notcp
```

### Reverse mode (client <- server)
1. run my client
```
# no TLS
client.exe -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234

# TLS
client.exe -r -h 0.0.0.0 -p 5000 -H 0.0.0.0 -P 1234 -s
```
2. run my server
```
# no TLS
server.exe -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53

# TLS
server.exe -r -h 192.168.0.5 -p 1234 -H 192.168.1.10 -P 60000 -a 192.168.1.1 -b 53 -s
```
3. connect to my client from other udp clients
```
dig @127.0.0.1 -p 5000 google.com +notcp
```

## Notes
### How to change server privatekey and certificate
- server
    1. run x64 Native Tools Command Prompt for VS 2022
    2. set environment variable
    ```
    set OPENSSL_CONF=C:\Program Files\Common Files\SSL\openssl.cnf
    ```
    3. generate server privatekey, publickey and certificate
    ```
    openssl ecparam -genkey -name prime256v1 -out server-key-pair.pem
    
    openssl ec -in server-key-pair.pem -outform PEM -out server-private.pem
    
    openssl ec -in server-key-pair.pem -outform PEM -pubout -out server-public.pem
    
    openssl req -new -sha256 -key server-key-pair.pem -out server.csr
    openssl x509 -days 3650 -req -signkey server-private.pem < server.csr > server.crt
    openssl x509 -text -noout -in server.crt
    ```
    4. copy the server privatekey and certificate
    ```
    type server-private.pem
    type server.crt
    ```
    5. paste the privatekey and certificate into serverkey.h file
    ```
    char server_privatekey[] = "-----BEGIN EC PRIVATE KEY-----\n"\
    "MHcCAQEEIPAB7VXkdlfWvOL1YKr+cxGLhx69g/eqUjncU1D9hkUdoAoGCCqGSM49\n"\
    "AwEHoUQDQgAErAWMtToIcsL5fGF+DKZhMRy9m1WR3ViC7nrLokou9A/TMPr2DMz9\n"\
    "O7kldBsGkxFXSbXcUfjk6wyrgarKndpK0A==\n"\
    "-----END EC PRIVATE KEY-----\n";

    char server_certificate[] = "-----BEGIN CERTIFICATE-----\n"\
    "MIIBhTCCASsCFB47Pqx2Ko4ZXD5bCsGaaTP1Zjh8MAoGCCqGSM49BAMCMEUxCzAJ\n"\
    "BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\n"\
    "dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjMwMTE1MTIwODA3WhcNMzMwMTEyMTIwODA3\n"\
    "WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY\n"\
    "SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"\
    "QgAErAWMtToIcsL5fGF+DKZhMRy9m1WR3ViC7nrLokou9A/TMPr2DMz9O7kldBsG\n"\
    "kxFXSbXcUfjk6wyrgarKndpK0DAKBggqhkjOPQQDAgNIADBFAiEAqknImSukXNY+\n"\
    "fkuuFbDFkte9mZM3Xy/ArE7kDIMt4nwCIHdlJRn0Cf18VQbpLessgklsk/gX59uo\n"\
    "jrsksbPHQ50h\n"\
    "-----END CERTIFICATE-----\n";
    ```
    6. set environment variable
    ```
    set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
    set LIB=%LIB%;C:\Program Files\OpenSSL\lib
    set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib
    ```
    7. build
    ```
    cd udp-packet-forwarder\Windows\server
    compile.bat
    ```

- client
    1. copy server.crt file to udp-packet-forwarder\Windows\client directory
    ```
    copy server.crt udp-packet-forwarder\Windows\client\server.crt
    ```
    2. modify client.c file (if you change the certificate filename or directory path)
    ```
    char server_certificate_filename[256] = "server.crt";	// server certificate file name
    char server_certificate_file_directory_path[256] = ".";	// server certificate file directory path
    ```
    3. run x64 Native Tools Command Prompt for VS 2022
    4. set environment variable
    ```
    set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
    set LIB=%LIB%;C:\Program Files\OpenSSL\lib
    set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib
    ```
    5. build (if you change the certificate filename or directory path)
    ```
    cd udp-packet-forwarder\Windows\client
    compile.bat
    ```

### How to change server cipher suite (TLS1.2, TLS1.3)
- server
    1. select cipher suite(TLS1.2) and check
    ```
    openssl ciphers -v "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256"
    ```
    2. select cipher suite(TLS1.3) [https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_ciphersuites.html](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_ciphersuites.html)
    ```
    TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384
    TLS_CHACHA20_POLY1305_SHA256
    TLS_AES_128_CCM_SHA256
    TLS_AES_128_CCM_8_SHA256
    ```
    3. modify server.c file
    ```
    char cipher_suite_tls1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";	// TLS1.2
    char cipher_suite_tls1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";	// TLS1.3
    ```
    4. run x64 Native Tools Command Prompt for VS 2022
    5. set environment variable
    ```
    set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
    set LIB=%LIB%;C:\Program Files\OpenSSL\lib
    set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib
    ```
    6. build
    ```
    cd udp-packet-forwarder\Windows\server
    compile.bat
    ```

