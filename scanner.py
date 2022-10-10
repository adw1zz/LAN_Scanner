import scapy.all as scapy
import socket
import requests
import time
from mac_vendor_lookup import MacLookup
	
def scan(ip):	
	 
	print("\n------------------------------------------------")
	first = scapy.ARP(pdst=ip)
	
	mc = MacLookup()

	second = scapy.Ether()
	second.dst = 'ff:ff:ff:ff:ff:ff'
	arp_req = second/first
	answered_list = scapy.srp(arp_req, timeout = 5, verbose = False)[0]
	
	el = answered_list[0]
	vendor = mc.lookup(el[1].hwdst)
	
	print("My Ip: "+el[1].pdst+"\t" + "MAC: "+ el[1].hwdst+"\t"+"Vendor: "+vendor+"\n-------------------------------------")
	
	clients_list = []
	
	for elem in answered_list:
		vendor='Unknown'
		try:
			vendor = mc.lookup(elem[1].hwsrc)
		except:
			pass
		
		client_dict = {"ip": elem[1].psrc, "mac": elem[1].hwsrc, "vendor": vendor}
		clients_list.append(client_dict)
	return clients_list

def printRes(result_list):
	
	print("IP\t\t\tMAC Address\t\t\tVendor\n--------------------------------------------")
	
	for client in result_list:
		print(client["ip"]+"\t\t"+ client["mac"]+"\t\t"+client["vendor"])	
		
	

print("Enter ip: ")		
printRes(scan(input()+"/24"))
