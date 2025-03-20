```bash
Task 1
From what domain is the VBS script downloaded?
```
Sử dụng tính năng  `find a packet` ![bilde](https://github.com/user-attachments/assets/70dff075-1b76-4ba5-8509-49e03c06617b)
Đầu tiên, tìm trong `packet list`, option `string`:
![bilde](https://github.com/user-attachments/assets/f5604590-2dee-4e79-9021-06703e9419e2)

```bash
Task 5
What likely legit binary was downloaded to the victim machine?
```
continue using `find a packet`, with option `packet byte` & `string`:
![bilde](https://github.com/user-attachments/assets/66e9c0ee-640b-406a-a0cd-5f794febf096)

```bash
Task 8

```
Wrong hash, wrong TLSH, VirtusTotal detected my script.ahk as script.ahk.txt T.T
Oh, after downloading the original `jvtobaqj` file and looking through it again, the random words were commented out, not the main script (of course LOL). Did not touch the file at all -> VirusTotal -> correct detection

```bash
Task 10
What is the user-agent string of the infected machine?
```
By using `find a packet` with option `Packet detail` & `String` `User-Agent` there appeared to be only one infected machine but how do we know how many machines again??/
