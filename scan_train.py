#make ranges for everything-ports
from scapy.all import *
import ipaddress
import warnings
from concurrent.futures import ThreadPoolExecutor
import warnings
#Check a ports
def CheckPort(port,ip,TF):
    if TF:
        for i in range(port[0],port[1]):
            ans,unans=sr(IP(dst=str(ip))/TCP(sport=3333,dport=i,flags="S"),
        timeout=3,verbose=0)
    
            for (s,r) in ans:
                if(s[TCP].dport==r[TCP].sport and r[TCP].flags=="SA"):
                    print("port %s is open" %(s[TCP].dport))
    else:
        ans,unans=sr(IP(dst=str(ip))/TCP(sport=3333,dport=port,flags="S"),
        timeout=3,verbose=0)
    
        for (s,r) in ans:
            if(s[TCP].dport==r[TCP].sport and r[TCP].flags=="SA"):
                print("port %s is open" %(s[TCP].dport))
def DNSearch(ip):
    ans,unans=sr(IP(dst=str(ip))/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")),
    timeout=3,verbose=0)
    if ans and ans[UDP]:
        print("there is a web using ip:"+ip)
#ALive
def Alive(ip):
    ans,unans=sr(IP(dst=str(ip))/ICMP(type=8),timeout=3, verbose=0)
    if ans:
        print("Ip %s is alive\n"%ip)
#def RangesIP():
def RangesIp(ip):
    iprange=ipaddress.ip_address(ip[0].strip())
    endip=ipaddress.ip_address(iprange)
    endip=int(endip)+1
    if len(ip)==2:
        endip=ipaddress.ip_address(ip[1])
        endip=int(endip)+1
    iprange=int(iprange)
    ranges=[]
    for i in range(iprange,endip):
        ranges.append(ipaddress.ip_address(i))
    with ThreadPoolExecutor(max_workers=25) as ex:
        ex.map(Alive,ranges)

    
def is_int(num_str):
    try:
        int(num_str)
        return True
    except ValueError:
        return False
#check what he wanna do
def Check(words):
#options
    W=["-p","-a","-d"]
#port we are taking
    P=[]
#check all the order
    for i in range(len(words)-1):
#if he wanna check ports
        if words[i]=="-p":
#checking ports
            TF=0
            for i2 in range(i+1,len(words)-1):
                w=words[i2]
                if('-' in w and w[0] is not '-'):
                    checkIfPorts=w.split('-')
                    if len(checkIfPorts)==2 and is_int(checkIfPorts[0]) and is_int(checkIfPorts[1]):
                        P.append(int(checkIfPorts[0]))
                        P.append(int(checkIfPorts[1]))
                        TF=1

                        break
                if w[0] is not "-":
                    P.append(int(words[i2]))                    
                else:
                    break;
#send it to def
            CheckPort(P,words[-1],TF)


#check using DNS
        if(words[i]=="-d"):
            DNSearch(words[-1])
#if u wanna check if the ips in range alive
        if words[i]=="-a":
            if('-' in words[-1]):
                splited=words[-1].split('-')
                RangesIp(splited)
            else:
                Alive(words[-1])
            
            

def Scanning():
    Ip_range=input("Entered the code... \n")
    #Ip_range="Scanning -p 80 3333 443 -d 192.168.1.1"
    words=Ip_range.split()
    print(words)
    
    if(words[0].lower()==("Scanning").lower()):
        W=words[1:]
        Check(W)
    elif(words[0]=="help"):
        print("-a:Checking if the ip is alive\n-p:checking if ports open\n-d:DnsSearch")
    else:
        print("wrong typo")
warnings.filterwarnings("ignore")
while(1):
    Scanning()
