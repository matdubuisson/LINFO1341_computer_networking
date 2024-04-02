import os, sys

import numpy as np
import matplotlib.pyplot as plt

import pyshark
from pyshark import FileCapture
from pyshark.packet.packet import Packet
from pyshark.packet.layers.xml_layer import XmlLayer
from pyshark.packet.fields import LayerFieldsContainer

dns_types = {
    1: "A",
    28: "AAAA",
    18: "AFSDB",
    42: "APL",
    257: "CAA",
    60: "CNDSKEY",
    59: "CDS",
    37: "CERT",
    5: "CNAME",
    62: "CSYNC",
    49: "DHCID",
    32769: "DLV",
    39: "DNAME",
    48: "DNSKEY",
    43: "DS",
    108: "EU148",
    109: "EUI164",
    13: "HINFO",
    55: "HIP",
    65: "HTTPS",
    45: "IPSECKEY",
    25: "KEY",
    36: "KX",
    29: "LOC",
    15: "MX",
    35: "NAPTR",
    2: "NS",
    47: "NSEC",
    50: "NSEC3",
    51: "NSEC3PARAM",
    61: "OPENPGKEY",
    12: "PTR",
    17: "RP",
    46: "RRSIG",
    24: "SIG",
    53: "SMIMEA",
    6: "SOA",
    33: "SRV",
    44: "SSHFP",
    64: "SVCB",
    32768: "TA",
    249: "TKEY",
    52: "TLSA",
    250: "TSIG",
    16: "TXT",
    256: "URI",
    63: "ZONEMD",
    255: "*",
    252: "AXFR",
    251: "IXFR",
    41: "OPT"
}

tcp_flags = {
    1: "FIN",
    2: "SYN",
    4: "RST",
    8: "PSH",
    16: "ACK",
    32: "URG"
}

def main(filename, accuracy=60, interval=10, parsing="sizes", minimal=float("-inf"), maximal=float("+inf"), printable=False, key_log_file=None):
    parsing = parsing.split(",")
    use_only_one = False
    use_only_sizes = False
    use_authors = False
    use_selection = "selection" in parsing
    use_anti_selection = "anti_selection" in parsing
    anti_selection = []
    
    if use_selection:
        if use_anti_selection:
            selection = parsing[parsing.index("selection") + 1:parsing.index("anti_selection")]
            anti_selection = parsing[parsing.index("anti_selection") + 1:]
        else:
            selection = parsing[parsing.index("selection") + 1:]
    else:
        selection = []
        
        if use_anti_selection:
            anti_selection = parsing[parsing.index("anti_selection") + 1:]
           
    def match_selection(token):
        if not use_selection and not use_anti_selection:
            return True
        else:
            for each in anti_selection:
                if each in token:
                    return False
            
            for each in selection:
                if each in token:
                    return True
                
            return False
    
    if key_log_file == None:
        capture = FileCapture(filename)
    else:
        capture = FileCapture(
            filename,
            override_prefs={'ssl.keylog_file': os.path.abspath('sslkeys_google.log')},
            debug=True
        )
    
    by_type = [{}, {}]
    by_time = [{}, {}]
    size_i = 0
    size_tmp = 0
    sizes = []
    cnames = {}
    dns_results = {}
    
    clock = float(capture[0].sniff_timestamp)
    
    i = 0
    j = 0
    
    for packet in capture:
        if i == 0:
            print("{0} packets computed".format(j))
        
        i = (i + 1) % 1000
        
        j += 1
            
        # packet: Packet = packet
        frame_info: XmlLayer = packet.frame_info
        
        protocols: LayerFieldsContainer = frame_info.get("protocols")
        protocols = str(protocols).split(":")
        
        dic_type = dic_time = None
        
        time = int((float(packet.sniff_timestamp) - clock)) // accuracy
        
        if "ips" in parsing:
            dic_type = by_type[0]
            dic_time = by_time[0]
            use_only_one = True
            types = (str(protocols[2]),)
        elif "tcp-flags" in parsing:
            dic_type = by_type[0]
            dic_time = by_time[0]
            use_only_one = True
            
            if "tcp" in protocols:
                code = int(packet.tcp.flags, 16)
                result = ""
                
                for key in tcp_flags.keys():
                    if key & code:
                        result += tcp_flags[key] + " "
                types = (result,)
            else:
                continue
        elif "authors" in parsing:
            use_authors = True
            if "ip" in protocols:
                types = (
                    (False, "ipv4-> " + str(packet.ip.src)),
                    (True, "ipv4-> " + str(packet.ip.dst))
                )
            elif "ipv6" in protocols:
                types = (
                    (False, "ipv6-> " + str(packet.ipv6.src)),
                    (True, "ipv6-> " + str(packet.ipv6.dst))
                )
        elif "sizes" in parsing:
            dic_type = by_type[0]
            dic_time = by_time[0]
            use_only_sizes = True
            
            if use_selection:
                found = False
                
                for each in protocols[3:]:
                    if match_selection(each):
                        found = True
                        break
                    
                if not found:
                    continue
            
            size_tmp += int(frame_info.get("len"))
            
            if size_i == accuracy:
                size_i = 0
                v = size_tmp / accuracy
                
                if v < minimal or v > maximal:
                    v = 0.0
                
                sizes.append(v)
                size_tmp = 0
            else:
                size_i += 1
                
            types = []
        elif "protocols" in parsing:
            dic_type = by_type[0]
            dic_time = by_time[0]
            use_only_one = True
            
            if len(protocols) <= 3:
                continue
            else:
                types = protocols[3:]
        elif "linked-protocols" in parsing:
            dic_type = by_type[0]
            dic_time = by_time[0]
            use_only_one = True
            
            if len(protocols) <= 3:
                continue
            else:
                types = (":".join(protocols[3:]),)
        elif "dns" in parsing and "dns" in protocols:
            index = protocols.index("dns")
            
            dns_layer: XmlLayer = packet.layers[index - 1]
            
            if str(dns_layer.get_field("flags_response")) == "True":
                type_id = int(dns_layer.get_field("qry_type"))

                type_id = int(dns_layer.get_field("resp_type"))
                dic_type = by_type[1]
                dic_time = by_time[1]
                
                types = []
                
                if "a" in dns_layer.field_names:
                    types.append("A")
                if "aaaa" in dns_layer.field_names:
                    types.append("AAAA")
                if "cname" in dns_layer.field_names:
                    types.append("CNAME")
                if "soa_mname" in dns_layer.field_names:
                    types.append("SOA")
            else:
                type_id = int(dns_layer.get_field("qry_type"))
                dic_type = by_type[0]
                dic_time = by_time[0]
                types = [dns_types.get(type_id, "Undefined dns type {0}".format(type_id)),]
            
        elif "dns-names" in parsing and "dns" in protocols:
            index = protocols.index("dns")
            
            dns_layer: XmlLayer = packet.layers[index - 1]
            
            if str(dns_layer.get_field("flags_response")) == "True":
                type = str(dns_layer.get_field("resp_name"))
                dic_type = by_type[1]
                dic_time = by_time[1]
                
                if "cname" in dns_layer.field_names:
                    cnames[type] = True
                else:
                    cnames[type] = False
                    
                tmp = str(dns_layer.get_field("qry_name"))
                    
                if dns_results.get(tmp, None) == None:
                    dns_results[tmp] = {}
                    
                dns_results[tmp]["RESP"] = type
                    
                if "a" in dns_layer.field_names:
                    dns_results[tmp]["A"] = dns_layer.get_field("a")
                if "aaaa" in dns_layer.field_names:
                    dns_results[tmp]["AAAA"] = dns_layer.get_field("aaaa")
                if "cname" in dns_layer.field_names:
                    dns_results[tmp]["CNAME"] = dns_layer.get_field("cname")
                if "soa_mname" in dns_layer.field_names:
                    dns_results[tmp]["SOA"] = dns_layer.get_field("soa_mname")
            else:
                type = str(dns_layer.get_field("qry_name"))
                dic_type = by_type[0]
                dic_time = by_time[0]
                
            types = (str(type),)
        else:
            continue

        for type in types:
            if isinstance(type, tuple):
                b, type = type
            else:
                b = None
                
            if b != None:
                if b:
                    dic_type = by_type[1]
                    dic_time = by_time[1]
                else:
                    dic_type = by_type[0]
                    dic_time = by_time[0]
            
            if use_selection and "linked-protocols" in parsing:
                found = False
                
                for each in type.split(":"):
                    if match_selection(each):
                        found = True
                        break
                    
                if not found:
                    continue
            elif not match_selection(type):
                continue
            
            if dic_type.get(type, None) == None:
                dic_type[type] = 1
            else:
                dic_type[type] += 1
                
            if dic_time.get(time, None) == None:
                dic_time[time] = {}
            
            if dic_time[time].get(type, None) == None:
                dic_time[time][type] = 1
            else:
                dic_time[time][type] += 1
    
    if minimal != float("-inf") or maximal != float("+inf"):
        for each in by_time:
            for time in tuple(each.keys()):
                for type in tuple(each[time].keys()):
                    if each[time][type] < minimal or each[time][type] > maximal:
                        each[time].pop(type)
                        
                if len(each[time]) == 0:
                    each.pop(time)
                        
        for each in by_type:
            for type in tuple(each.keys()):
                if each[type] < minimal or each[type] > maximal:
                    each.pop(type)
    
    if printable:
        for type in by_type[0]:
            print("0,", type, ",", by_type[0][type], ", empty")
            
        for type in by_type[1]:
            print("1,", type, ",", by_type[1][type], ",", cnames.get(type, None))
    
    if use_only_sizes:
        n = len(sizes)
        plt.plot(np.arange(0, n, 1), sizes)
        plt.xlabel("Packets order")
        plt.ylabel("Averages for {0} packets".format(accuracy))
    else:
        if "all" in parsing or "graphs" in parsing:
            def aux(dic_time, label=""):
                times = list(dic_time.keys())
                
                if len(times) == 0:
                    return {}, []
                
                n = max(times) + 1
                lines_time = {}
            
                for time in times:
                    for type in dic_time[time]:
                        if lines_time.get(type, None) == None:
                            lines_time[type] = [0] * n#np.zeros(n, int)
                        
                        lines_time[type][time] = dic_time[time][type]
                        
                legends = []
                
                for key in lines_time.keys():
                    legends.append(label + str(key))
                        
                return lines_time, legends
            
            legends = []
            
            if use_only_one or "both" in parsing or "queries" in parsing or "sources" in parsing:
                queries_types_on_times, legends = aux(by_time[0], "Q : " if not use_authors else "Src : ")

            if not use_only_one and ("both" in parsing or "answers" in parsing or "destinations" in parsing):
                answers_types_on_times, tmp = aux(by_time[1], "A : " if not use_authors else "Dst : ")
                legends.extend(tmp)
            
            def auxBis(lines_time):
                for type in lines_time.keys():
                    plt.plot(np.arange(0, len(lines_time[type]), 1, int), lines_time[type])
                    
            if use_only_one or "both" in parsing or "queries" in parsing or "sources" in parsing:
                auxBis(queries_types_on_times)
            
            if not use_only_one and ("both" in parsing or "answers" in parsing or "destinations" in parsing):
                auxBis(answers_types_on_times)
                    
            plt.legend(legends)
            plt.xlabel("1 unit == {0} seconds".format(accuracy))
            plt.ylabel("N requests")
        
        if "all" in parsing or "bars" in parsing:
            if not use_only_one and "both" in parsing:
                for type in by_type[0].keys():
                    if by_type[1].get(type, None) == None:
                        by_type[1][type] = 0
                        
                for type in by_type[1].keys():
                    if by_type[0].get(type, None) == None:
                        by_type[0][type] = 0
                
                labels = []
                queries_values = []
                answers_values = []
                
                for type in by_type[0].keys():
                    if not use_selection or type in parsing:
                        labels.append(str(type))
                        queries_values.append(by_type[0][type])
                        answers_values.append(by_type[1][type])
                    
                n = len(labels)
                xs = np.arange(0, n, 1, float)
                    
                fig = plt.figure()
                ax = fig.add_subplot(111)
                
                ax.bar(xs - 0.2, queries_values, width=0.4, align="center", color="blue")
                ax.bar(xs + 0.2, answers_values, width=0.4, align="center", color="red")
                ax.set_xticks(xs)
                ax.set_xticklabels(labels)
                ax.legend(("queries", "answers"))
                
                for i in xs:
                    j = int(i)
                    ax.text(i - 0.2, queries_values[j], queries_values[j])
                    ax.text(i + 0.2, answers_values[j], answers_values[j])
            elif use_only_one or "queries" in parsing or "sources" in parsing:
                plt.bar(by_type[0].keys(), by_type[0].values(), align="center", color="blue")
                
                if not use_only_one:
                    plt.legend(("queries",))
                
                i = 0
                for key in by_type[0].keys():
                    plt.text(i, by_type[0][key], by_type[0][key])
                    i += 1
            elif "answers" in parsing or "destinations" in parsing:
                plt.bar(by_type[1].keys(), by_type[1].values(), align="center", color="red")
                plt.legend(("answers",))
                
                i = 0
                for key in by_type[1].keys():
                    plt.text(i, by_type[1][key], by_type[1][key])
                    i += 1
                    
    if "dns-names" in parsing:
        print(dns_results)
    
    plt.title(parsing)
    plt.show()
        
if __name__ == "__main__":
    try:
        filename = sys.argv[sys.argv.index("-f") + 1]
        accuracy = int(sys.argv[sys.argv.index("-a") + 1])
        parsing = sys.argv[sys.argv.index("-p") + 1]
        printable = "--print" in sys.argv
        key_log_file = sys.argv[sys.argv.index("-klf") + 1] if "-klf" in sys.argv else None
        
        if "--min" in sys.argv:
            minimal = float(sys.argv[sys.argv.index("--min") + 1])
        else:
            minimal = float("-inf")
            
        if "--max" in sys.argv:
            maximal = float(sys.argv[sys.argv.index("--max") + 1])
        else:
            maximal = float("+inf")
    except ValueError or IndexError:
        print("Please provide a file name '-f <filename>', '-a <accuracy>' and '-p <parsing>' and '--min x' and '--max y'")
        
    main(filename=filename, accuracy=accuracy, parsing=parsing, minimal=minimal, maximal=maximal, printable=printable, key_log_file=key_log_file)
