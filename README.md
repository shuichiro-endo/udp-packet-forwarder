# udp packet forwarder

udp packet forwarder (ipv4, ipv6)

This tool does not forward icmp and icmpv6 packets (Port unreachable, etc.).

## How it works
### Normal mode (client -> server)
```mermaid
sequenceDiagram
    participant A as udp client
    participant B as my client
    participant C as my server
    participant D as target server
    C->>C: run my server and listen (tcp)
    B->>B: run my client
    B->>+C: connect (tcp)
    C-->>B: 
    alt tls flag is on
    B->>+C: SSL connect
    C-->>B: 
    end
    C->>C: bind (udp)
    B->>B: bind (udp)
    loop until forwarder timeout
        alt send udp packet
        A->>B: send udp packet (udp)
        B->>C: send udp data (tcp or tcp over tls)
        C->>D: send udp packet (udp)
        end
        alt recv udp packet
        D->>C: recv udp packet (udp)
        C->>B: recv udp data (tcp or tcp over tls)
        B->>A: recv udp packet (udp)
        end
    end
```

### Reverse mode (client <- server)
```mermaid
sequenceDiagram
    participant A as udp client
    participant B as my client
    participant C as my server
    participant D as target server
    B->>B: run my client and listen (tcp)
    C->>C: run my server
    C->>+B: connect (tcp)
    B-->>C: 
    alt tls flag is on
    B->>+C: SSL connect
    C-->>B: 
    end
    C->>C: bind (udp)
    B->>B: bind (udp)
    loop until forwarder timeout
        alt send udp packet
        A->>B: send udp packet (udp)
        B->>C: send udp data (tcp or tcp over tls)
        C->>D: send udp packet (udp)
        end
        alt recv udp packet
        D->>C: recv udp packet (udp)
        C->>B: recv udp data (tcp or tcp over tls)
        B->>A: recv udp packet (udp)
        end
    end
```

## License
This project is licensed under the MIT License.

See the [LICENSE](https://github.com/shuichiro-endo/udp-packet-forwarder/blob/main/LICENSE) file for details.

