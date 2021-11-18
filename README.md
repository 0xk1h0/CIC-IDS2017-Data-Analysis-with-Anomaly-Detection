# CIC-IDS2017-Data-Analysis with Anomaly Detection
Intrusion Detection Evaluation Dataset (CIC-IDS2017) Data Analysis
A collaborative project between the Communications Security Establishment (CSE) & the Canadian Institute for Cybersecurity (CIC)
- https://www.unb.ca/cic/datasets/ids-2017.html

* CICIDS2017 dataset contains benign and the most up-to-date common attacks, which resembles the true real-world data (PCAPs).

* The data capturing period started at 9 a.m., Monday, July 3, 2017 and ended at 5 p.m. on Friday July 7, 2017, for a total of 5 days. Monday is the normal day and only includes the benign traffic. The implemented attacks include Brute Force FTP, Brute Force SSH, DoS, Heartbleed, Web Attack, Infiltration, Botnet and DDoS. They have been executed both morning and afternoon on Tuesday, Wednesday, Thursday and Friday.

### Victim and attacker networks information

* Firewall: 205.174.165.80, 172.16.0.1

* DNS+ DC Server: 192.168.10.3

* Outsiders (Attackers network)
  - Kali: 205.174.165.73
  - Win: 205.174.165.69, 70, 71
* Insiders (Victim network)
  - Web server 16 Public: 192.168.10.50, 205.174.165.68
  - Ubuntu server 12 Public: 192.168.10.51, 205.174.165.66
  - Ubuntu 14.4, 32B: 192.168.10.19
  - Ubuntu 14.4, 64B: 192.168.10.17
  - Ubuntu 16.4, 32B: 192.168.10.16
  - Ubuntu 16.4, 64B: 192.168.10.12
  - Win 7 Pro, 64B: 192.168.10.9
  - Win 8.1, 64B: 192.168.10.5
  - Win Vista, 64B: 192.168.10.8
  - Win 10, pro 32B: 192.168.10.14
  - Win 10, 64B: 192.168.10.15
  - MAC: 192.168.10.25

* Monday, July 3, 2017
   - Benign (Normal human activities) # 월요일 - 정상 데이터입니다.
   1. Data Normalize
      - tshark -nnr Monday-WorkingHours.pcap -Tfields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.proto -e tcp.flags -e tcp.flags.syn -e tcp.flags.ack -e ip.len -e frame.len -e udp.port | awk '{print strftime("%Y-%m-%d %H:%M:%S", $1) "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6 "\t" $7 "\t" $8 "\t" $9 "\t" $10 "\t" $11}'|gzip > Monday.tsv.gz
 ![image](https://user-images.githubusercontent.com/47383452/142409135-35a1d163-b21b-4937-a350-019b66becde6.png)
      - Inside flow visualization(192.168.XX.XX) : Web Server(10.50), DNS+ DC Server(10.3), Ubuntu Server(10.51),etc,,
   2. DNS+DC Server, Web Server, Ubuntu Server Availability Analysis(DNS+DC, 웹 서버, 우분투 서버 가용성 분석)
   - Server Availability, Check Session per Second, Packet per Second, Byte per Second
     1) DNS+DC
      * ```zcat Monday.tsv.gz | grep 192.168.10.3 | awk '$8=="0x00000002"{print $2, "SYN";next}$8=="0x00000012"{print $2, "SYNACK";next}' | sort | uniq -c | tr "\n" "|" | sed 's/SYNACK|/SYNACK\n/g'| tr "|" " " | awk '{print $2 "\t" $1 "\t" $4 "\t" $4/$1*100}' | feedgnuplot --domain --timefmt "%H:%M:%S" --lines --points --title "DNS+DC Server Side Rate" --xlab "time" --y2lab "pkts" --ylab "SYN/SYNACK RATE" --ymax 120 --y2max 50 --y2 0 --legend 0 "SYN" --legend 1 "SYNACK" --legend 2 "SYNACK / SYN"```
![image](https://user-images.githubusercontent.com/47383452/142415540-b92cb635-2348-46e8-83f1-b4cc0d4313af.png)

     2) Web Server
       *
     3) Ubuntu Server
       *
* Tuesday, July 4, 2017
  - Brute Force
  - FTP-Patator (9:20 – 10:20 a.m.)
  - SSH-Patator (14:00 – 15:00 p.m.)
  - Attacker: Kali, 205.174.165.73
  - Victim: WebServer Ubuntu, 205.174.165.68 (Local IP: 192.168.10.50)
  - NAT Process on Firewall:
  - Attack: 205.174.165.73 -> 205.174.165.80 (Valid IP of the Firewall) -> 172.16.0.1 -> 192.168.10.50
  - Reply: 192.168.10.50 -> 172.16.0.1 -> 205.174.165.80 -> 205.174.165.73
* Wednesday, July 5, 2017
   - DoS / DDoS
   - DoS slowloris (9:47 – 10:10 a.m.)
   - DoS Slowhttptest (10:14 – 10:35 a.m.)
   - DoS Hulk (10:43 – 11 a.m.)
   - DoS GoldenEye (11:10 – 11:23 a.m.)
   - Attacker: Kali, 205.174.165.73
   - Victim: WebServer Ubuntu, 205.174.165.68 (Local IP192.168.10.50)
   - NAT Process on Firewall:
   - Attack: 205.174.165.73 -> 205.174.165.80 (Valid IP of the Firewall) -> 172.16.0.1 -> 192.168.10.50
   - Reply: 192.168.10.50 -> 172.16.0.1 -> 205.174.165.80 -> 205.174.165.73
   - Heartbleed Port 444 (15:12 - 15:32)
   - Attacker: Kali, 205.174.165.73
   - Victim: Ubuntu12, 205.174.165.66 (Local IP192.168.10.51)
