import argparse
import os
from analysis import perform_in_depth_analysis,identify_security_concerns,analyze_pcap,generate_enhanced_executive_summary
from insights import generate_recommendation
from report import generate_pdf_report

def banner():
    font=r"""

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

def main(pcap_file):
    print(f"Analyzing {pcap_file}...")

    # Check if the "result" directory exists
    if not os.path.exists("result"):
        os.makedirs("result")
    
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
    generate_pdf_report(data, analysis, executive_summary, concerns, recommendations)

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description='Analyze a PCAP file.')
    parser.add_argument('--pcap_file', type=str, help='Path to the PCAP file')
    args = parser.parse_args()
    main(args.pcap_file)
