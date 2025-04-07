# Sherlock Scenario

> In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows system. Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. This lab is inspired by that campaign and guides participants through the initial access stage of the campaign.

## Artefacts
There is only 1 file inside the zip file, which is a MS Windows event log:
```bash
$ file Microsoft-Windows-Sysmon-Operational.evtx 
```
![bilde](https://hackmd.io/_uploads/ByLH2g-0kg.png)

## Solutions

**Task 1**
*How many Event logs are there with Event ID 11?*
```bash
$ chainsaw search -t 'Event.System.EventID: =11' Microsoft-Windows-Sysmon-Operational.evtx
```
![bilde](https://hackmd.io/_uploads/rkXG2eZRJx.png)

**Task 2**
*Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?*
```bash
$ chainsaw search -t 'Event.System.EventID: =1' Microsoft-Windows-Sysmon-Operational.evtx
```
![bilde](https://hackmd.io/_uploads/HkJmeWWRJl.png)
`C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`

**Task 3**
*Which Cloud drive was used to distribute the malware?*

Context Sysmon event id: 11:FileCreate and 22:DNSEvent
First, use event id 11 to query file creation, grep with "Preventio":
```bash
$ chainsaw search -t 'Event.System.EventID: =11' Microsoft-Windows-Sysmon-Operational.evtx | grep "Preventivo" -B 10 -A 10
```
![bilde](https://hackmd.io/_uploads/H1U7jfW0kl.png)
from the above image, we can see the malware "Preventivo..." was downloaded using Mozilla Firefox, this process's id is `4292`.
Then, use event id 22 and grep with "4292":
![bilde](https://hackmd.io/_uploads/H1WIjGZ01g.png)
`dropbox`

**Task 4**
*For many of the files it wrote to disk, the initial malicious file used a defense evasion technique called Time Stomping, where the file creation date is changed to make it appear older and blend in with other files. What was the timestamp changed to for the PDF file?*

Context Sysmon event id: 2: A process changed a file creation time
```bash
$ chainsaw search -t 'Event.System.EventID: =2' Microsoft-Windows-Sysmon-Operational.evtx chainsaw | grep "pdf" -A 10 
```
![bilde](https://hackmd.io/_uploads/BkcnzGZ0kg.png)
`2024-01-14 08:10:06`

**Task 5**
*The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename.*

Context Sysmon event id: 11: FileCreate 
```bash
$ chainsaw search -t 'Event.System.EventID: =11' Microsoft-Windows-Sysmon-Operational.evtx | grep "once" -B 10 -A 10
```
![bilde](https://hackmd.io/_uploads/SyF-YG-0kg.png)
`C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd`

**Task 6**
*The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?*

Context Sysmon event id: 22
```bash
$ chainsaw search -t 'Event.System.EventID: =22' Microsoft-Windows-Sysmon-Operational.evtx
```
There were only 3 hits and only one of them was DNS query by the malware:
![bilde](https://hackmd.io/_uploads/H18_4f-Cyx.png)

`www.example.com`

**Task 7**
*Which IP address did the malicious process try to reach out to?*

From the previous task:
![bilde](https://hackmd.io/_uploads/r1Rf4MbRyx.png)
`93.184.216.34`

**Task 8**
*The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?*

Context Sysmon event id: 5:Process terminated 
```bash
$ chainsaw search -t 'Event.System.EventID: =5' Microsoft-Windows-Sysmon-Operational.evtx
```
![bilde](https://hackmd.io/_uploads/rJ4XvMW0Je.png)
`2024-02-14 03:41:58`

## Additional knowledge
**Sysmon log**

**Palo Alto's Unit42**

**UltraVNC**

---
*9r3y*
