import os
import json
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from matplotlib import colors as mcolors
from matplotlib import ticker
from mpl_toolkits import mplot3d
from operator import itemgetter, attrgetter

#from SignatureAttackStagePredictor import SignatureAttackStagePredictor
import sys


def main():
    """
    :param ____:       PARAMETER DESCRIPTION
    :return result:    RETURN DESCRIPTION
    """
    #target = input("Enter path to target suricata json/log file: ")
    filetype = "j"
    #filetype = "l"
    #filetype = input("Specify filetype, .json (j) or .log (l): ")
    #extras = input("Generate additional graphs (y/n): ") # Simpler graphs are optional and take significant time
    extras = "n"
    #octet_limit = input("Limit attacker IP octets (1-4): ")
    octet_limit = 1
    #target = "/home/sxo6099/Desktop/fast.log"
    target = "/home/sxo6099/Desktop/1541388897_6754_UTC_110318_1400to2345_suricata_alert_clean_raw.json"
    #target = "/home/sxo6099/Desktop/UNSW_pcaps_22_1_2015/aggregate/aggregate.log"
    file = open(target, "r")
    data = file.read()
    if filetype == "j":
        lines = data.replace("{", "\n")
        lines = data.splitlines()
    elif filetype == "l":
        lines = data.splitlines()
    file.close()
    table = {}

    # For each entry of the alert file, use the timestamp as a dict key
    if filetype == "j":
        for i in lines:
            i = i.strip()
            i = i.replace(",", " ")
            i = i.replace("\"", " ")
            i = i.replace(":", " ")
            i = i.replace("\"", "")
            i = i.replace("\'", "")
            cur = i.split()
            while (" ") in cur:
                cur.remove(" ")

            src = ""
            src_port = ""
            dest = ""
            port = "" # Destination port
            time = ""
            sig = ""
            rcode = ""
            for select in range(0, len(cur)-1):
                if cur[select] == "src_ip":
                    src = cur[select+1]
                if cur[select] == "src_port":
                    src_port = cur[select+1]
                if cur[select] == "dest_ip":
                    dest = cur[select+1]
                if cur[select] == "dest_port":
                    port = cur[select+1]
                if cur[select] == "timestamp":
                    time = cur[select+1]
                    time += cur[select+2]
                    time += cur[select+3]

                if cur[select] == "alert_category":
                    append_offset = 1
                    while cur[select+append_offset] != "alert_signature_id" and cur[select+append_offset] != "alert_gid":
                        sig += cur[select+append_offset]
                        append_offset += 1
                if cur[select] == "rcode":
                    rcode = cur[select+1]

            if sig == "":
                sig = rcode
            if time != "" and sig != "" and port != "": # Json data not all perfectly formatted, need some error checking
                table[time] = [src, dest, port, src_port, sig]
            
    elif filetype == "l":
        for i in lines:
            cur = i.split()
            time = cur[0]
            src = cur[-3].split(":")[0]
            src_port = cur[-3].split(":")[1]
        
            dest = cur[-1].split(":")[0]
            port = cur[-1].split(":")[1]

            sig = ""
            appending = False
            for k in range(len(cur)):
                if cur[k] == "[Priority:":
                    appending = False
                if appending:
                    sig += " "
                    sig += cur[k]
                if cur[k] == "[Classification:":
                    appending = True
                    sig += cur[k]
            
            #print(sig)
            table[cur[0]] = [src, dest, port, src_port, sig]

    # Creat dicts with relevant statistical data for future reference
    src_count = {}
    dest_count = {}
    port_count = {}
    src_port_count = {}
    src_IPport_count = {}
    dest_IPport_count = {}
    sig_count_table = {}
    for j in table:
        # Source IP tallying
        if table[j][0] in src_count:
            src_count[table[j][0]] += 1
        else:
            src_count[table[j][0]] = 1

        # Destination IP tallying
        if table[j][1] in dest_count:
            dest_count[table[j][1]] += 1
        else:
            dest_count[table[j][1]] = 1

        # Destination port tallying
        if table[j][2] in port_count:
            port_count[table[j][2]] += 1
        else:
            port_count[table[j][2]] = 1

        # Source port tallying
        if table[j][3] in src_port_count:
            src_port_count[table[j][3]] += 1
        else:
            src_port_count[table[j][3]] = 1

        # Source IP + Port tallying
        temp = table[j][0] + (":") + table[j][3]
        if temp in src_IPport_count:
            src_IPport_count[temp] += 1
        else:
            src_IPport_count[temp] = 1

        # Destination IP + Port tallying
        temp = table[j][1] + (":") + table[j][2]
        if temp in dest_IPport_count:
            dest_IPport_count[temp] += 1
        else:
            dest_IPport_count[temp] = 1

        # Alert signature tallying
        if table[j][4] in sig_count_table:
            sig_count_table[table[j][4]] += 1
        else:
            sig_count_table[table[j][4]] = 1

    # Use dictionaries of frequencies to determine which is most common
    common_src = 0
    common_src_count = 0
    for x in src_count:
        if src_count[x] > common_src_count:
            common_src = x
            common_src_count = src_count[x]

    common_dest = 0
    common_dest_count = 0
    for y in dest_count:
        if dest_count[y] > common_dest_count:
            common_dest = y
            common_dest_count = dest_count[y]
    
    common_port = 0
    common_port_count = 0
    for z in port_count:
        if port_count[z] > common_port_count:
            common_port = z
            common_port_count = port_count[z]

    src_common_port = 0
    src_common_port_count = 0
    for a in src_port_count:
        if src_port_count[a] > src_common_port_count:
            src_common_port = a
            src_common_port_count = src_port_count[a]

    src_common_IPport = 0
    src_common_IPport_count = 0
    for b in src_IPport_count:
        if src_IPport_count[b] > src_common_IPport_count:
            src_common_IPport = b
            src_common_IPport_count = src_IPport_count[b]

    dest_common_IPport = 0
    dest_common_IPport_count = 0
    for b in dest_IPport_count:
        if dest_IPport_count[b] > dest_common_IPport_count:
            dest_common_IPport = b
            dest_common_IPport_count = dest_IPport_count[b]

    common_sig = ""
    common_sig_count = 0
    for b in sig_count_table:
        if sig_count_table[b] > common_sig_count:
            common_sig = b
            common_sig_count = sig_count_table[b]

    # Use Stephen Moskal's script
    """
    attk_stg_pred = SignatureAttackStagePredictor()
    pred_model = SignatureAttackStagePredictor()
    unique_sigs = []
    for iterate in table:
        if table[iterate][4] not in unique_sigs:
            unique_sigs.append(table[iterate][4])
    attk_stg = pred_model.predict(signatures)
    print(attk_stg)
    """
    
    # Print stats
    print("Most common source IP: " + str(common_src) + ", occuring "
          + str(common_src_count) + " times.")
    print("Most common source port: " + str(src_common_port) + ", occuring "
          + str(src_common_port_count) + " times.")
    print("Most common source IP/port combination : " + str(src_common_IPport)
          + ", occuring " + str(src_common_IPport_count) + " times.")
    print("Most common target IP: " + str(common_dest)
          + ", occuring " + str(common_dest_count) + " times.")
    print("Most common target port: " + str(common_port)
          + ", occuring " + str(common_port_count) + " times.")
    print("Most common target IP/port combination : " + str(dest_common_IPport)
          + ", occuring " + str(dest_common_IPport_count) + " times.")
    print("Most common alert signature : " + str(common_sig)
          + ", occuring " + str(common_sig_count) + " times.")


    # Graphing Section
    test1 = []
    test2 = []
    src_graph = sorted(src_port_count)
    for c in src_graph:
        test1.append(c)
        test2.append(src_port_count[c])
        
    test3 = []
    test4 = []
    dest_graph = sorted(port_count)
    for d in dest_graph:
        test3.append(d)
        test4.append(port_count[d])

    # Setup for complex scatterplots
    attackerIPvictimPort = []
    attackerIPport = []
    times = []
    signatures = []
    Dports = []
    for iterate in table:
        attackerIPvictimPort.append([table[iterate][0], table[iterate][2]])
        attackerIPport.append([table[iterate][0], table[iterate][3]])
        times.append(iterate)
        signatures.append(table[iterate][4])
        Dports.append(int(table[iterate][2]))
        # victimPort.append(table[iterate][2])

    attackerIP = []
    victimPort = []
    attackerIPvictimPort = sorted(attackerIPvictimPort, key=itemgetter(1, 0))
    for iterate in attackerIPvictimPort:
        attackerIP.append(iterate[0])
        victimPort.append(iterate[1])


    attackerIP = []
    attackerPort = []
    attackerIPport = sorted(attackerIPport, key=itemgetter(1, 0))
    for iterate in attackerIPport:
        attackerIP.append(iterate[0])
        attackerPort.append(iterate[1])

    # 2D scatterplots with some interesting info, but significantly increase processing time
    if extras == "y":
        #plt.plot(port_count.keys(), port_count.values(), label = "Source Ports")
        plot1 = plt.figure(1)
        plt.scatter(test1, test2, label = "Source Ports", alpha=0.5)
        plt.suptitle("Source Port Count")

    if extras == "y":
        plot2 = plt.figure(2)
        plt.scatter(test3, test4, label = "Destination Ports", alpha=0.5)
        plt.suptitle("Destination Port Count")

    if extras == "y":
        plot3 = plt.figure(3)
        plt.scatter(attackerIP, victimPort, label = "Attacker IP to Victim Port", alpha=0.05)
        #plt.yticks(np.arange(0, 65500, 5000))
        plt.suptitle("Attacker IP to Victim Port Mapping")

    if extras == "y":
        plot4 = plt.figure(4)
        plt.scatter(attackerIP, attackerPort, label = "Attacker IP/Port Combinations", alpha=0.05)
        plt.suptitle("Attacker IP to Port Mapping")

    if extras == "y":
        plot5 = plt.figure(5)
        plt.scatter(times, signatures, label = "Attack Signatures Over Time", alpha=0.05)
        plt.suptitle("Attack Signatures Over Time")

    # 3D scatterplots
    plot6 = plt.figure(6)
    ax = plt.axes(projection='3d')
    simple_times = []
    for item in times:
        if filetype == "j":
            simplify = item[11:18]
            simple_times.append(float(simplify.replace(":", "")))
        elif filetype == "l":
            simplify = item[11:16]
            simple_times.append(float(simplify.replace(":", "")))
    print("Times range from: " + times[0] + " to: " + times[-1])
    unique_sigs = []
    for item in signatures:
        if item not in unique_sigs:
            unique_sigs.append(item)
            
    sig_nums = []
    for num in range(0, len(unique_sigs)):
        sig_nums.append(num+1)
        print("Signature: " + unique_sigs[num] + " corresponds to: " + str(num+1))
        
    numerical_sigs = []
    for item in signatures:
        numerical_sigs.append(unique_sigs.index(item)+1)
        
    ax.scatter(simple_times, numerical_sigs, Dports, label = "Signatures, Ports, Times", alpha=0.30)
    ax.text2D(0.05, 0.95, "Port Attack Signatures Over Time", transform=ax.transAxes)
    #ax.suptitle("Port Attack Signatures Over Time")

    plot7 = plt.figure(7)
    ax2 = plt.axes(projection='3d')
    simple_ips = []
    complex_ips = []
    for item in attackerIP:
        octets = item.split(".")
        if octet_limit == 1:
            gen_src = octets[0]
            
            comp_src = str(octets[0])
            
        elif octet_limit == 2:
            gen_src = str(octets[0])
            gen_src += str(octets[1])
            
            comp_src = str(octets[0])
            comp_src += "."
            comp_src += str(octets[1])
            
        elif octet_limit == 3:
            gen_src = str(octets[0])
            gen_src += str(octets[1])
            gen_src += str(octets[2])
            
            comp_src = str(octets[0])
            comp_src += "."
            comp_src += str(octets[1])
            comp_src += "."
            comp_src += str(octets[2])
        elif octet_limit == 4:
            gen_src = str(octets[0])
            gen_src += str(octets[1])
            gen_src += str(octets[2])
            gen_src += str(octets[3])

            comp_src = str(octets[0])
            comp_src += "."
            comp_src += str(octets[1])
            comp_src += "."
            comp_src += str(octets[2])
            comp_src += "."
            comp_src += str(octets[3])

        simple_ips.append(int(gen_src))
        #if comp_src not in complex_ips:
        complex_ips.append(comp_src)

    number_ips = []
    for number in range(0, len(simple_ips)):
        number_ips.append(number)

    # Loop for finding information on CPTC team data
    team_times = []
    team_sigs = []
    team_ips = []
    team_comp = False # True when looking at CPTC 2018 team info, False otherwise
    if team_comp:
        for i in range(0, len(complex_ips)-1):
            if complex_ips[i].split(".")[2] == "254" and complex_ips[i].split(".")[0] == "10":
                team_ips.append(int(complex_ips[i].split(".")[3]))
                team_sigs.append(numerical_sigs[i])
                team_times.append(simple_times[i])
        simple_ips = team_ips
        numerical_sigs = team_sigs
        simple_times = team_times

    
    ax2.scatter(simple_times, numerical_sigs, simple_ips, label = "Signatures, General Attacker IPs, Times", alpha=0.30)
    #ax2.set_zscale('log')
    ax2.text2D(0.05, 0.95, "Source IP Attack Signatures Over Time", transform=ax.transAxes)

    # Radar chart graphing

    src_odds = {}
    src_total = 0
    for item in src_count:
        src_total += src_count[item]
    for item in src_count:
        src_odds[item] = src_count[item]/src_total

    dest_odds = {}
    dest_total = 0
    for item in dest_count:
        dest_total += dest_count[item]
    for item in dest_count:
        dest_odds[item] = dest_count[item]/dest_total

    port_odds = {}
    port_total = 0
    for item in port_count:
        port_total += port_count[item]
    for item in port_count:
        port_odds[item] = port_count[item]/port_total

    src_port_odds = {}
    src_port_total = 0
    for item in src_port_count:
        src_port_total += src_port_count[item]
    for item in src_port_count:
        src_port_odds[item] = src_port_count[item]/src_port_total

    sig_odds = {}
    sig_total = 0
    for item in sig_count_table:
        sig_total += sig_count_table[item]
    for item in sig_count_table:
        sig_odds[item] = sig_count_table[item]/sig_total
    sig_count_table

    likeliehood_table = {}
    for item in table:
        likeliehood = 0
        likeliehood += src_odds[table[item][0]]
        likeliehood += dest_odds[table[item][1]]
        likeliehood += port_odds[table[item][2]]
        likeliehood += src_port_odds[table[item][3]]
        likeliehood += sig_odds[table[item][4]]

        likeliehood_table[item] = likeliehood
    least_likely = item
    for item in likeliehood_table:
        if likeliehood_table[item] < likeliehood_table[least_likely]:
            least_likely = item
    
    print("The most unique attack occured at: " + least_likely)
    print("With a likeliehood of: " + str(likeliehood_table[least_likely]))
    print("Shown here: ")
    print(table[least_likely])


    categories = ["Signature", "Source IP", "Source Port", "Destination IP", "Destination Port"]
    final_sig = table[least_likely][4]
    final_src_IP = table[least_likely][0]
    final_src_port = table[least_likely][3]
    final_dest_IP = table[least_likely][1]
    final_dest_port = table[least_likely][2]
    final_stats = [final_sig, final_src_IP, final_src_port, final_dest_IP, final_dest_port]


    radar = go.Figure()
    radar.add_trace(go.Scatterpolar(r=final_stats,
        theta=categories,
        fill='toself',
        name='Least Likely'))


    radar.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True)),
        showlegend=False)

    # Second radar chart
    categories2 = ["Distinct Adversary IPs", "Distinct Victim Ports", "Alert Categories", "Arrival Speed of Alerts"]
    dist_IPs = []
    dist_ports = []
    alert_cats = len(unique_sigs)
    start_time = simple_times[0]
    end_time = simple_times[-1]
    timeframe = start_time-end_time
    if filetype == "l": # Hardcoded time amounts as formatting on strings is making time measuring bad for radar chart
        timeframe = 163.42
    else:
        timeframe = 577.44
    alert_total = len(table.keys())

    for i in table:
        if table[i][0] not in dist_IPs:
            dist_IPs.append(table[i][0])
        if table[i][2] not in dist_ports:
            dist_ports.append(table[i][2])

    # Currently using arbitrary, hard coded scaling based on CPTC 2018 and UNSW datasets
    radar_stats = [(len(dist_IPs)/60), (len(dist_ports)/66000), (alert_cats/20), ((alert_total/timeframe)/800)]
    radar2 = go.Figure()
    radar2.add_trace(go.Scatterpolar(r=radar_stats,
        theta=categories2,
        fill='toself',
        name='Radar Chart'))


    radar2.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True)),
        showlegend=False)
    
    radar.show()
    radar2.show()
    plt.show()

if __name__ == '__main__':
    main()
