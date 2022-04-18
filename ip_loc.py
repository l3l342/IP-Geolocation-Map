'''
Made by Ben

Api credits:
    https://ipwhois.app/
    free 10000 requests per month

Have fun :)
'''

import urllib.request
import pyshark
from ipaddress import ip_address
import json


class IpLocation:
    def __init__(self):
        self.ip_unsorted = []
        self.ip = []
        self.privat_or_bogon_ip = []
        self.my_ip = None

    def scan_ips(self):
        file = pyshark.LiveCapture(output_file="sample.pcap")
        print("sniffing...")
        print("make sure to have traffic")
        file.sniff(1000)

        cap = pyshark.FileCapture("sample.pcap", only_summaries=True)

        for packet in cap:
            line = str(packet)
            reformatting = line.split(" ")
            self.ip_unsorted.append(reformatting[3])    #destination ip
            self.ip_unsorted.append(reformatting[2])    #source ip
        cap.close()
        return self.ip_unsorted

    def filter_ips(self, ip_to_sort):
        for ip in ip_to_sort:
            if ip == 'ff:ff:ff:ff:ff:ff':
                continue
            if ":" in ip:
                continue
            if ip_address(ip).is_private:
                self.privat_or_bogon_ip.append(ip)
            else:
                self.ip.append(ip)
        return self.ip

    @staticmethod
    def remove_double(double_ips):
        ips = list(set(double_ips))
        return ips

    def ip_info(self, ip):
        if ip.lower() == "me":
            req = "https://ipwhois.app/json/"
            response = urllib.request.urlopen(req)
            data = json.load(response)
            self.my_ip = data["ip"]
            return data
        else:
            req = "https://ipwhois.app/json/{0}".format(ip)
            response = urllib.request.urlopen(req)
            data = json.load(response)
            return data