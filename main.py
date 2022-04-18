from ip_loc import *


def main():
    iploc = IpLocation()

    ip_scan = iploc.scan_ips()
    ips = iploc.remove_double(ip_scan)
    filtered_ip = iploc.filter_ips(ips)

    print("public ips: ", filtered_ip)
    print(len(filtered_ip))
    print("bogon or privat ips: ", iploc.privat_or_bogon_ip)

    # map with geodata
    m = folium.Map(location=[52.374, 4.8897], zoom_start=2)

    for ip in filtered_ip:
        data = iploc.ip_info(ip)
        print(ip)
        if data["success"]:
            lat = data["latitude"]
            long = data["longitude"]
            folium.Marker(location=[lat, long], popup=ip).add_to(m)

    data = iploc.ip_info("me")
    lat = data["latitude"]
    long = data["longitude"]
    folium.Marker(location=[lat, long], popup=f"""ME  {iploc.my_ip}""").add_to(m)
    m.save("map.html")

    print("Open 'map.html' to see the geolocation of the ip ")

if __name__ == "__main__":
    i = input("press y to start sniffing ")
    if i == "y":
        main()
    else:
        exit()