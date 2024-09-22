import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO
from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw
from scapy.layers.http import HTTP
from collections import Counter, defaultdict
from ipaddress import ip_address
import statistics
import datetime
import networkx as nx
import os
import argparse

def safe_decode(data, encoding='utf-8', errors='ignore'):
    if isinstance(data, bytes):
        return data.decode(encoding, errors=errors)
    return str(data)

def analyze_pcap(file_path):
    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return None
    except Exception as e:
        print(f"An error occurred while reading the PCAP file: {str(e)}")
        return None

    data = {
        'total_packets': len(packets),
        'protocols': Counter(),
        'src_ips': Counter(),
        'dst_ips': Counter(),
        'ports': Counter(),
        'packet_sizes': [],
        'tcp_flags': Counter(),
        'time_distribution': defaultdict(int),
        'conversations': defaultdict(int),
        'ttl_values': [],
        'dns_queries': Counter(),
        'http_methods': Counter(),
        'packet_rate': 0,
        'start_time': None,
        'end_time': None,
        'ip_geolocation': defaultdict(Counter),
        'payload_data': [],
        'tcp_window_sizes': [],
        'tcp_retransmissions': Counter(),
        'udp_lengths': [],
        'icmp_types': Counter(),
        'ssl_versions': Counter(),
        'application_data': defaultdict(Counter)
    }

    for packet in packets:
        if data['start_time'] is None:
            data['start_time'] = packet.time
        data['end_time'] = packet.time

        if IP in packet:
            ip_layer = packet[IP]
            data['src_ips'][ip_layer.src] += 1
            data['dst_ips'][ip_layer.dst] += 1
            data['protocols'][ip_layer.proto] += 1
            data['packet_sizes'].append(len(packet))
            data['ttl_values'].append(ip_layer.ttl)
            data['conversations'][(ip_layer.src, ip_layer.dst)] += 1

            timestamp = datetime.datetime.fromtimestamp(float(packet.time))
            data['time_distribution'][timestamp.hour] += 1

            # Simulated geolocation (replace with actual geolocation service in production)
            data['ip_geolocation'][ip_layer.src]['country'] += 1
            data['ip_geolocation'][ip_layer.dst]['country'] += 1

            if TCP in packet:
                tcp_layer = packet[TCP]
                data['ports'][tcp_layer.sport] += 1
                data['ports'][tcp_layer.dport] += 1
                data['tcp_flags'][tcp_layer.flags] += 1
                data['tcp_window_sizes'].append(tcp_layer.window)

                if tcp_layer.flags & 0x04:  # RST flag
                    data['tcp_retransmissions'][(ip_layer.src, ip_layer.dst)] += 1

                if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                    if HTTP in packet:
                        http_layer = packet[HTTP]
                        if hasattr(http_layer, 'Method'):
                            method = safe_decode(http_layer.Method)
                            data['http_methods'][method] += 1
                elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                    data['ssl_versions']['TLSv1.2'] += 1  # Simulated SSL version detection

            elif UDP in packet:
                udp_layer = packet[UDP]
                data['ports'][udp_layer.sport] += 1
                data['ports'][udp_layer.dport] += 1
                data['udp_lengths'].append(udp_layer.len)

                if DNS in packet:
                    dns_layer = packet[DNS]
                    if dns_layer.qr == 0 and dns_layer.qd:  # It's a query
                        query = safe_decode(dns_layer.qd.qname)
                        data['dns_queries'][query] += 1

            elif packet.haslayer('ICMP'):
                icmp_layer = packet['ICMP']
                data['icmp_types'][icmp_layer.type] += 1

            # Simulated application-layer protocol detection
            if Raw in packet:
                payload = packet[Raw].load
                data['payload_data'].append(len(payload))
                if b'HTTP' in payload:
                    data['application_data']['HTTP'][ip_layer.src] += 1
                elif b'SSH' in payload:
                    data['application_data']['SSH'][ip_layer.src] += 1

    if data['start_time'] and data['end_time']:
        duration = data['end_time'] - data['start_time']
        data['packet_rate'] = data['total_packets'] / duration if duration > 0 else 0

    return data

def perform_in_depth_analysis(data):
    analysis = []

    # Protocol Analysis
    top_protocols = data['protocols'].most_common(5)
    analysis.append("Protocol Distribution:")
    for proto, count in top_protocols:
        percentage = (count / data['total_packets']) * 100
        analysis.append(f"  - {proto}: {count} packets ({percentage:.2f}%)")

    # Traffic Pattern Analysis
    top_src_ips = data['src_ips'].most_common(5)
    top_dst_ips = data['dst_ips'].most_common(5)
    analysis.append("\nTop 5 Source IP Addresses:")
    for ip, count in top_src_ips:
        percentage = (count / data['total_packets']) * 100
        analysis.append(f"  - {ip}: {count} packets ({percentage:.2f}%)")
    analysis.append("\nTop 5 Destination IP Addresses:")
    for ip, count in top_dst_ips:
        percentage = (count / data['total_packets']) * 100
        analysis.append(f"  - {ip}: {count} packets ({percentage:.2f}%)")

    # Port Analysis
    top_ports = data['ports'].most_common(10)
    analysis.append("\nTop 10 Ports:")
    for port, count in top_ports:
        percentage = (count / data['total_packets']) * 100
        analysis.append(f"  - Port {port}: {count} packets ({percentage:.2f}%)")

    # Packet Size Analysis
    avg_size = statistics.mean(data['packet_sizes'])
    median_size = statistics.median(data['packet_sizes'])
    std_dev = statistics.stdev(data['packet_sizes'])
    analysis.append(f"\nPacket Size Statistics:")
    analysis.append(f"  - Average: {avg_size:.2f} bytes")
    analysis.append(f"  - Median: {median_size:.2f} bytes")
    analysis.append(f"  - Standard Deviation: {std_dev:.2f} bytes")

    # TCP Flags Analysis
    if data['tcp_flags']:
        analysis.append("\nTCP Flags Distribution:")
        for flags, count in data['tcp_flags'].most_common():
            percentage = (count / sum(data['tcp_flags'].values())) * 100
            analysis.append(f"  - {flags}: {count} ({percentage:.2f}%)")

    # Time Distribution Analysis
    analysis.append("\nTraffic Distribution by Hour:")
    for hour, count in sorted(data['time_distribution'].items()):
        percentage = (count / data['total_packets']) * 100
        analysis.append(f"  - Hour {hour}: {count} packets ({percentage:.2f}%)")

    # Conversation Analysis
    top_conversations = sorted(data['conversations'].items(), key=lambda x: x[1], reverse=True)[:5]
    analysis.append("\nTop 5 Conversations:")
    for (src, dst), count in top_conversations:
        percentage = (count / data['total_packets']) * 100
        analysis.append(f"  - {src} <-> {dst}: {count} packets ({percentage:.2f}%)")

    # TTL Analysis
    avg_ttl = statistics.mean(data['ttl_values'])
    analysis.append(f"\nAverage TTL: {avg_ttl:.2f}")

    # DNS Query Analysis
    if data['dns_queries']:
        analysis.append("\nTop 5 DNS Queries:")
        for query, count in data['dns_queries'].most_common(5):
            analysis.append(f"  - {query}: {count} times")

    # HTTP Method Analysis
    if data['http_methods']:
        analysis.append("\nHTTP Method Distribution:")
        for method, count in data['http_methods'].items():
            percentage = (count / sum(data['http_methods'].values())) * 100
            analysis.append(f"  - {method}: {count} ({percentage:.2f}%)")

    # TCP Window Size Analysis
    if data['tcp_window_sizes']:
        avg_window = statistics.mean(data['tcp_window_sizes'])
        analysis.append(f"\nAverage TCP Window Size: {avg_window:.2f} bytes")

    # UDP Length Analysis
    if data['udp_lengths']:
        avg_udp_length = statistics.mean(data['udp_lengths'])
        analysis.append(f"\nAverage UDP Datagram Length: {avg_udp_length:.2f} bytes")

    # ICMP Type Analysis
    if data['icmp_types']:
        analysis.append("\nICMP Type Distribution:")
        for icmp_type, count in data['icmp_types'].most_common():
            percentage = (count / sum(data['icmp_types'].values())) * 100
            analysis.append(f"  - Type {icmp_type}: {count} ({percentage:.2f}%)")

    # SSL/TLS Version Analysis
    if data['ssl_versions']:
        analysis.append("\nSSL/TLS Version Distribution:")
        for version, count in data['ssl_versions'].items():
            percentage = (count / sum(data['ssl_versions'].values())) * 100
            analysis.append(f"  - {version}: {count} ({percentage:.2f}%)")

    # Application-Layer Protocol Analysis
    if data['application_data']:
        analysis.append("\nDetected Application-Layer Protocols:")
        for protocol, ips in data['application_data'].items():
            analysis.append(f"  - {protocol}: {sum(ips.values())} occurrences")

    return analysis

def identify_security_concerns(data):
    concerns = []

    # Check for potential port scanning
    if len(data['dst_ips']) / len(data['src_ips']) > 10:
        concerns.append("Possible port scanning detected")

    # Check for potential DDoS
    top_dst_ip = data['dst_ips'].most_common(1)[0]
    if (top_dst_ip[1] / data['total_packets']) > 0.5:
        concerns.append(f"High traffic concentration to {top_dst_ip[0]}, potential DDoS")

    # Check for unusual ports
    unusual_ports = [port for port, count in data['ports'].items() if port not in [80, 443, 22, 53] and count > 100]
    if unusual_ports:
        concerns.append(f"High traffic on unusual ports: {', '.join(map(str, unusual_ports))}")

    # Check for high rate of TCP retransmissions
    if data['tcp_retransmissions']:
        total_tcp = sum(data['tcp_flags'].values())
        retrans_rate = sum(data['tcp_retransmissions'].values()) / total_tcp
        if retrans_rate > 0.05:
            concerns.append(f"High TCP retransmission rate: {retrans_rate:.2%}")

    # Check for potential SSL/TLS vulnerabilities
    if 'SSLv3' in data['ssl_versions'] or 'TLSv1.0' in data['ssl_versions']:
        concerns.append("Deprecated SSL/TLS versions detected")

    # Check for potential DNS tunneling
    if data['dns_queries']:
        avg_query_length = statistics.mean(len(q) for q in data['dns_queries'])
        if avg_query_length > 50:
            concerns.append("Unusually long DNS queries detected, potential DNS tunneling")

    return concerns

def generate_recommendation(data, concerns):
    recommendations = []

    if "Possible port scanning detected" in concerns:
        recommendations.append("Implement stricter firewall rules and investigate potential port scanning activities.")

    if any("potential DDoS" in concern for concern in concerns):
        recommendations.append("Activate DDoS mitigation measures and investigate traffic to the most targeted IP.")

    if any("unusual ports" in concern for concern in concerns):
        recommendations.append("Review and potentially restrict traffic on identified unusual ports.")

    if data['packet_rate'] > 1000:
        recommendations.append("Consider network capacity upgrades to handle high traffic volume.")

    if any("High TCP retransmission rate" in concern for concern in concerns):
        recommendations.append("Investigate network congestion or potential packet loss issues.")

    if any("Deprecated SSL/TLS versions detected" in concern for concern in concerns):
        recommendations.append("Upgrade SSL/TLS configurations to use only secure versions (TLS 1.2 or higher).")

    if any("DNS tunneling" in concern for concern in concerns):
        recommendations.append("Implement DNS query monitoring and filtering to detect and prevent DNS tunneling attempts.")

    if not recommendations:
        recommendations.append("Continue monitoring for any significant changes in traffic patterns.")

    return recommendations

def create_pie_chart(data, title, filename):
    plt.figure(figsize=(10, 6))
    plt.pie(data.values(), labels=data.keys(), autopct='%1.1f%%', startangle=90)
    plt.title(title)
    plt.axis('equal')
    plt.savefig(filename)
    plt.close()

def create_bar_chart(data, title, xlabel, ylabel, filename):
    plt.figure(figsize=(12, 6))
    plt.bar(data.keys(), data.values())
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def create_time_series_chart(data, title, filename):
    plt.figure(figsize=(12, 6))
    plt.plot(data.keys(), data.values())
    plt.title(title)
    plt.xlabel('Hour of Day')
    plt.ylabel('Number of Packets')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def create_network_graph(data, filename):
    G = nx.Graph()
    for (src, dst), weight in data['conversations'].items():
        G.add_edge(src, dst, weight=weight)

    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color='lightblue', 
            node_size=500, font_size=8, font_weight='bold')
    edge_weights = nx.get_edge_attributes(G, 'weight')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_weights)
    plt.title("Network Communication Graph")
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def generate_enhanced_executive_summary(data, concerns, recommendations):
    total_duration = data['end_time'] - data['start_time']
    top_src_ip = data['src_ips'].most_common(1)[0]
    top_dst_ip = data['dst_ips'].most_common(1)[0]
    top_port = data['ports'].most_common(1)[0]

    summary = f"""
Executive Summary of Network Traffic Analysis

1. Overview:
   - Total Packets: {data['total_packets']}
   - Duration: {total_duration:.2f} seconds
   - Average Packet Rate: {data['packet_rate']:.2f} packets/second

2. Traffic Distribution:
   - Top Source IP: {top_src_ip[0]} ({top_src_ip[1]} packets, {(top_src_ip[1]/data['total_packets']*100):.2f}% of total)
   - Top Destination IP: {top_dst_ip[0]} ({top_dst_ip[1]} packets, {(top_dst_ip[1]/data['total_packets']*100):.2f}% of total)
   - Most Active Port: {top_port[0]} ({top_port[1]} occurrences)

3. Protocol Analysis:
   - Primary Protocol: {data['protocols'].most_common(1)[0][0]}
   - Protocol Distribution: {', '.join([f"{k}:{v}" for k, v in data['protocols'].most_common(3)])}

4. Packet Size Statistics:
   - Average: {statistics.mean(data['packet_sizes']):.2f} bytes
   - Median: {statistics.median(data['packet_sizes']):.2f} bytes
   - Std Dev: {statistics.stdev(data['packet_sizes']):.2f} bytes

5. Security Concerns:
   {' '.join(concerns)}

6. Key Recommendations:
   {' '.join(recommendations)}

This summary provides a high-level overview of the network traffic captured in the PCAP file. For detailed analysis and visualizations, please refer to the full report.
"""
    return summary

def generate_pdf_report(data, analysis, executive_summary, concerns, recommendations):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Update existing styles
    styles['Heading2'].spaceAfter = 6
    styles['BodyText'].spaceBefore = 6
    styles['BodyText'].spaceAfter = 6

    # Title
    story.append(Paragraph("Network Traffic Analysis Report", styles['Title']))
    story.append(Spacer(1, 12))

    # Executive Summary
    story.append(Paragraph("Executive Summary", styles['Heading1']))
    story.append(Paragraph(executive_summary, styles['BodyText']))
    story.append(PageBreak())

    # Detailed Analysis
    story.append(Paragraph("Detailed Analysis", styles['Heading1']))
    for finding in analysis:
        if finding.startswith('\n'):
            story.append(Paragraph(finding[1:], styles['Heading2']))
        else:
            story.append(Paragraph(finding, styles['BodyText']))

    story.append(PageBreak())

    # Charts
    story.append(Paragraph("Visual Analysis", styles['Heading1']))

    # Protocol Distribution
    create_pie_chart(data['protocols'], 'Protocol Distribution', 'result/protocol_dist.png')
    story.append(Paragraph("Protocol Distribution", styles['Heading2']))
    story.append(Image('result/protocol_dist.png', 5*inch, 3*inch))
    story.append(Spacer(1, 12))

    # Top Source IPs
    create_bar_chart(dict(data['src_ips'].most_common(10)), 'Top 10 Source IPs', 'IP Address', 'Packet Count', 'result/top_src_ips.png')
    story.append(Paragraph("Top 10 Source IPs", styles['Heading2']))
    story.append(Image('result/top_src_ips.png', 6*inch, 3*inch))
    story.append(Spacer(1, 12))

    # Time Distribution
    create_time_series_chart(data['time_distribution'], 'Traffic Distribution by Hour', 'result/time_distribution.png')
    story.append(Paragraph("Traffic Distribution by Hour", styles['Heading2']))
    story.append(Image('result/time_distribution.png', 6*inch, 3*inch))
    story.append(Spacer(1, 12))

    # Network Graph
    create_network_graph(data, 'result/network_graph.png')
    story.append(Paragraph("Network Communication Graph", styles['Heading2']))
    story.append(Image('result/network_graph.png', 6*inch, 4*inch))
    story.append(Spacer(1, 12))

    story.append(PageBreak())

    # Security Concerns
    story.append(Paragraph("Security Concerns", styles['Heading1']))
    for concern in concerns:
        story.append(Paragraph(f"• {concern}", styles['BodyText']))

    # Recommendations
    story.append(Paragraph("Recommendations", styles['Heading1']))
    for recommendation in recommendations:
        story.append(Paragraph(f"• {recommendation}", styles['BodyText']))

    doc.build(story)
    buffer.seek(0)
    return buffer

def main(pcap_file):
    print(f"Analyzing {pcap_file}...")

    # Check if the "result" directory exists
    if not os.path.exists("result"):
        # Create the directory
        os.makedir("result")

    data = analyze_pcap(pcap_file)
    if data is None:
        return

    analysis = perform_in_depth_analysis(data)
    concerns = identify_security_concerns(data)
    recommendations = generate_recommendation(data, concerns)
    executive_summary = generate_enhanced_executive_summary(data, concerns, recommendations)

    print("Executive Summary:")
    print(executive_summary)

    print("\nGenerating PDF report...")
    pdf_buffer = generate_pdf_report(data, analysis, executive_summary, concerns, recommendations)

    with open("result/network_traffic_analysis_report.pdf", "wb") as f:
        f.write(pdf_buffer.getvalue())

    print("PDF report generated: network_traffic_analysis_report.pdf")
def banner():
    font="""

 _______  _______  _______  _______  _       _________ _       _________ _______ 
(  ____ )(  ____ \(  ___  )(  ____ )( (    /|\__   __/( (    /|\__    _/(  ___  )
| (    )|| (    \/| (   ) || (    )||  \  ( |   ) (   |  \  ( |   )  (  | (   ) |
| (____)|| |      | (___) || (____)||   \ | |   | |   |   \ | |   |  |  | (___) |
|  _____)| |      |  ___  ||  _____)| (\ \) |   | |   | (\ \) |   |  |  |  ___  |
| (      | |      | (   ) || (      | | \   |   | |   | | \   |   |  |  | (   ) |
| )      | (____/\| )   ( || )      | )  \  |___) (___| )  \  ||\_)  )  | )   ( |
|/       (_______/|/     \||/       |/    )_)\_______/|/    )_)(____/   |/     \|
                                                                                 
"""
    print(font)
if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description='Analyze a PCAP file.')
    parser.add_argument('--pcap_file', type=str, help='Path to the PCAP file')
    args = parser.parse_args()
    # Call the main function with the provided pcap file path
    main(args.pcap_file)
