import requests

def banner():
    ban=open("banner.txt","r")
    banne=ban.read()
    print(banne)
    print("This program is made by mr-shan")
    ban.close()
banner()
url=input("Enter the URL : ")
lists=open("subdomains.txt","r")
subs=lists.read()
lists.close()
subdomains=list(subs.split('\n'))

for i in subdomains:
    url2="https://{}.{}".format(i,url)
    try:
        r=requests.get(url2)
        if r.status_code!=404 and len(r.text)>0:
            print(i)
    except:
        pass


