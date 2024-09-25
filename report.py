import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO
import networkx as nx

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
    
    with open("result/network_traffic_analysis_report.pdf", "wb") as f:
        f.write(buffer.getvalue())

    print("PDF report generated: network_traffic_analysis_report.pdf")