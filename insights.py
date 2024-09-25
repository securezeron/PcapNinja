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