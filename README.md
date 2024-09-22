```
 _______  _______  _______  _______  _       _________ _       _________ _______ 
(  ____ )(  ____ \(  ___  )(  ____ )( (    /|\__   __/( (    /|\__    _/(  ___  )
| (    )|| (    \/| (   ) || (    )||  \  ( |   ) (   |  \  ( |   )  (  | (   ) |
| (____)|| |      | (___) || (____)||   \ | |   | |   |   \ | |   |  |  | (___) |
|  _____)| |      |  ___  ||  _____)| (\ \) |   | |   | (\ \) |   |  |  |  ___  |
| (      | |      | (   ) || (      | | \   |   | |   | | \   |   |  |  | (   ) |
| )      | (____/\| )   ( || )      | )  \  |___) (___| )  \  ||\_)  )  | )   ( |
|/       (_______/|/     \||/       |/    )_)\_______/|/    )_)(____/   |/     \|
                                                                                 
```
                                                                                 


# PCAP Ninja

A lightweight Python tool to analyze PCAP files and generate network traffic reports. It detects traffic patterns, security concerns, and provides insights based on the captured data.

## Features

- **Traffic Summary**: Analyze protocols, IPs, ports, packet sizes, and TCP flags.
- **Time Distribution**: View packet distribution by hour.
- **Top Conversations**: Identify top communication pairs.
- **Protocol Breakdown**: Statistics for HTTP, DNS, SSL, TCP, UDP, and ICMP.
- **Security Insights**: Detect potential DDoS attacks, port scanning, DNS tunneling, and deprecated SSL/TLS versions.
- **Recommendations**: Suggestions based on detected security concerns.

## Installation  
1. Clone the repository:

```bash
   git clone https://github.com/securezeron/PcapNinja.git
   cd pcapninja
```

2. Install dependeciies:
```bash
    pip install -r requirements.txt
```

3. Run the script
```bash
    python3 pcapninja.py --pcap_file example.pcap
```

## Future Scope
- Enhanced protocol support for newer protocols such as QUIC.
- Real-time analysis with live network capture and dynamic report generation.
- Machine learning integration to detect anomalous traffic patterns and potential threats.
- Web interface with real-time graphs and visual insights for easier data interpretation.
- Customizable reporting options allowing users to define specific metrics or data points of interest.
- API integration for interoperability with other monitoring and security tools.

## Contributions
Contributions are welcome! Please fork the repository and submit a pull request with your improvements.