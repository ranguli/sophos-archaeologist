from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

from pprint import PrettyPrinter

import csv
import ipaddress
from decouple import config

API_KEY = config("API_KEY")
otx = OTXv2(API_KEY)

# The encoding mode removes the infamous u'feff string from every line

public_ip_addresses = []
private_ip_addresses = []
hashes = []

pp = PrettyPrinter()
with open("artifacts.csv", "r", encoding="utf-8-sig") as csv_file:
    csv_reader = csv.DictReader(csv_file)
    line_count = 0
    for row in csv_reader:
        if "url" in row.get("Id"):
            if row.get("Type") == "ipaddress":
                ip = row.get("Name").split(":")[0]
                private = ipaddress.ip_address(ip).is_private
                if not private and ip not in public_ip_addresses:
                    public_ip_addresses.append(ip)
                    print("Getting information for {ip}".format(ip=ip))
                    result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'malware')
                    data = result.get("data")
                    if data:
                        detected = False
                        detection_providers = data[0].get("detections")
                        #print(detection_providers)
                        for provider in detection_providers:
                            print(detection_providers.get(provider))
                            #if detection_providers.get(provider):
                            #    print(provider)#.get(provider))
                        """
                        for detection in data:#:.get("detections"):
                            # Iterate providers like avast, avg, clamav, etc
                            for detector in detection.keys():
                                print(detector)
                             
                            malware_hash = entry.get("hash")
                            print("  > Found malware with hash: {hash}".format(hash=malware_hash))
                            if malware_hash not in hashes:
                                hashes.append(malware_hash)
                    #pp.pprint(result)
                        #exit()
                        """
                elif private and ip not in private_ip_addresses:
                    private_ip_addresses.append(ip)
            elif row.get("Type") == "url":
                url = row.get("Name")
                print("Getting information for {url}".format(url=url))
                #if not private and ip not in public_ip_addresses:
                #    public_ip_addresses.append(ip)
                #elif private and ip not in private_ip_addresses:
                #    private_ip_addresses.append(ip)

#print("\n".join(public_ip_addresses))

print(hashes)
