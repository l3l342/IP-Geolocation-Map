import urllib.request
import pyshark
import folium
from ipaddress import ip_address
import json


class IpLocation:
    def __init__(self):
        self.ip_unsorted = []
        self.ip = []
        self.privat_or_bogon_ip = []
        self.my_ip = None

    def scan_ips(self):
        cap = pyshark.FileCapture("sample.pcap", only_summaries=True)

        for packet in cap:
            line = str(packet)
            reformatting = line.split(" ")
            self.ip_unsorted.append(reformatting[3])
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

    def remove_double(self, double_ips):
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


def main():
    iploc = IpLocation()

    ip_scan = iploc.scan_ips()
    ips = iploc.remove_double(ip_scan)
    filtered_ip = iploc.filter_ips(ips)

    print("public ips: ", filtered_ip)
    print("bogon or privat ips: ", iploc.privat_or_bogon_ip)

    # map with geodata
    m = folium.Map(location=[52.374, 4.8897], zoom_start=2)

    for ip in filtered_ip:
        data = iploc.ip_info(ip)
        lat = data["latitude"]
        long = data["longitude"]
        folium.Marker(location=[lat, long], popup=ip, icon=folium.DivIcon(html=f"""<div style="font-family:Verdana; color:black">{ip}</div>""")).add_to(m)

    data = iploc.ip_info("me")
    lat = data["latitude"]
    long = data["longitude"]
    folium.Marker(location=[lat, long], popup=f"""ME  {iploc.my_ip}""").add_to(m)
    m.save("map.html")


if __name__ == "__main__":
    main()
