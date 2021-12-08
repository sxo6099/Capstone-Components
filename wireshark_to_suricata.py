# -*- coding: utf-8 -*-
"""WireShark_to_Suricata.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1FbOsIBVD7_EnxE73JN-Hq98VsVgiTX0J
"""

# installation and imports, mount drive
# !pip install idstools
# !pip install --upgrade suricata-update

from idstools import rule
# from google.colab import drive
import os


# drive.mount('/content/drive')

def suricataConfig():
    """
    Updates the current suricata ruleset based on
    latest Emerging Threats Open ruleset from currently installed
    snort version, or downloads ET open rules and updates
    :param ____:       PARAMETER DESCRIPTION
    :return result:    RETURN DESCRIPTION
    """
    os.system("idstools-rulecat -o /etc/suricata/rules") # May require sudo
    os.system("suricata-update") # Possibly redundant?

def main():
    """
    Given a target PCAP file or directory containing PCAPs,
    this program will ensure that the currently running verion
    of suricata is utilizing an up-to-date ruleset and will convert
    the targeted PCAPs into suricata alerts
    :param ____:       PARAMETER DESCRIPTION
    :return result:    RETURN DESCRIPTION
    """
    #targetPCAP = input("Enter path to target PCAP file: ")
    targetPCAP = "/home/sxo6099/Desktop/UNSW_pcaps_22_1_2015/10.pcap"
    # Not working due to permissions issues
    #outputAlert = input("Enter filename for produced Suricata Altert: ")
    suricataVerbosity = int(input("Enter suricata verbosity (0-4); "))
    suricataV = ""
    for x in range(0, suricataVerbosity):
        if (suricataV == ""):
            suricataV = "-"
        suricataV += "v"
    testPCAP = "/MyDrive/ACT3.1 Win7.pcapng"
    finalCommand = "suricata -c /etc/suricata/suricata.yaml -r " + targetPCAP + " " + suricataV
    suricataConfig()
    os.system(finalCommand)

"""
could possibly use following code snippet to replay PCAPs rather than replay option
which would also probably make live capture of packets significantly easier
suricata -c /etc/suricata/suricata.yaml -i eth0
tcpreplay -t -i eth0 /root/malware.pcap
"""

if __name__ == '__main__':
    main()
