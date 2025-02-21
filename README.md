# Attack and Detect With Wazuh

# Objective

SOC analysts must possess the essential skills to understand and detect attacks from both offensive and defensive perspectives. In this home lab, I simulated a business network called "ProjectX", introduced vulnerable configurations, performed a multi-phase end-to-end attack, and identified specific activities with detection rules and alerts created in Wazuh. 

This project was created by Grant Collins and can be accessed for free at https://projectsecurity.io/

# Skills Involved
  * Computer Networking
  * Firewall Configurations
  * Windows Active Directory
  * Phases of Cyber Attack - Reconnaissance, Initial Access, Lateral Movement, Privilege Escalation, Data Exfiltration, Persistence, Defense Evasion
  * Security Monitoring with Security Onion and Wazuh

# Skill Development
  Allows hands-on experience with tools like SIEMS, vulnerability scanners, and packet analyzers in a network context.
  Simulating incidents such as malware outbreaks or unauthorized access provides valuable experience in real-time response.

# End Goal
  Capture sensitive files and achieve persistence "backdoor" inside the business network so that we can log back in at our discretion. Our attacker is financially motivated, attempting to steal sensitive data. They have identified ProjectX    as a target organization to conduct their operations so they can extort and steal sensitive information, perhaps a username, password, and a propietary file.

# Tools
 * Microsoft Active Directory: A directory service developed by Microsoft used for managing and organizing network resources and permissions in a Windows environment.
   - Key Components:
      * Authentication: Verifies user identity using credentials like username and password
      * Authorization: Grants or denies access to network resources based on permissions
      * Centralized Management: Centralizes control over users, computers, and other resources
 
 * Wazuh: An open-source security monitoring platform that provides extended detection response (XDR) and System Information and Event Managment (SIEM) to protect cloud, container, and server workloads. It provides intrustion detection,              log analysis, vulnerability detection, and compliance reporting.
  Wazuh acts as a SIEM solution by collecting and analyzing security data from multiple sources, detecting threats in real-time and facilitating efficient incident response.

   A dedicated security server is critical for ensuring the performance, security, and scalability of your monitored analysis stack. Here's why:
    - Isolation: Running resource-intensive tools on a dedicated server prevents performance degradation caused by workloads on shared resources. Each application demands significant CPU, RAM, and disk I/O to function efficiently.
    - Security Context: Security tools process sensitive data, including logs and vulnerability scans. A dedicated server isolates sensitive data from unrelated systems.
    - Centralized Management: Simplifies monitoring and management, providing a single point for handling logs, alerts, and vulnerability data.

  (We will be using Wazuh as our open-source security tool to monitor and detect our simulated "attack")

   * Security Server Architecture
   
![Screenshot 2025-02-05 201101](https://github.com/user-attachments/assets/a939f5ec-c157-4247-a64f-d98686d17c1b)

  -- Running an XDR and SIEM services provide significant advantages to monitor, detect, prevent, and respond to security-related activity
   
 * Postfix: A popular open-source mail transfer agent (MTA) used for sending and receiving email on Unix-like operating systems.

![Screenshot 2025-02-05 195441](https://github.com/user-attachments/assets/a984ae85-7464-45f1-92cc-777af9e838f3)


# Security Implications
  
  * Enhanced Security Awareness:
    - Practicing in a simulated enterprise network allows users to understand and mitigate real-world vulnerabilities, improving their ability to secure actual networks
  * Controlled Environment for Testing:
    - Provides a safe space to explore exploits, malware behavior, and defense strategies without risking production systems or sensitive data
  * Experience with Enterprise Technologies:
    - Offers hands-on experience with technologies like Active Directory, VPNs, and SIEMS, critical for understanding attack surfaces and hardening systems

# Main Steps

1. Build an Enterprise Environment.

   The first step of the project involved building the enterprise environment using VirtualBox

![Screenshot 2025-02-05 173214](https://github.com/user-attachments/assets/c947abc2-27de-4d0b-b80b-503681dfdf4c)

![Screenshot 2025-02-05 180830](https://github.com/user-attachments/assets/08325ee8-787d-40de-a641-179148cb5614)

![Screenshot 2025-02-05 183736](https://github.com/user-attachments/assets/cdc01f42-6e80-4e00-8a3b-e6ee08cad4c0)

As shown in the topology above, the Email Server and three PC's were connected to the Active Directory domain controller.

2. Introduce Vulnerable Configurations

   In order to conduct the end-to-end attack, a number of vulnerable configurations were introduced into the environment.
     - Install and/or enable SSH (port 22) and RDP (port 3389) on relevant machines.
     - Install and enable Linux firewall on relevant machines.
     - Allow relevant services and ports (22 & 3389) on firewalls.
     - Create an intentionally weak password on the email server to create susceptiblity to brute force attack.

3. Create Detection Rules in Wazuh

   In order to detect activities from the end-to-end attack, three rules and alerts were created in Wazuh.

     * Rule to detect RDP logins. Windows does not have an event ID specifically for WinRM so a rule was created to detect authentication via Kerberos (which WinRM uses for remote connections) and successful logins. Specifically, two 
        filters were used:
         
         - data.win.eventdata.logonProcessName is Kerberos
         - data.win.system.eventID is 4624
     
     * Rule to monitor access of sensitive data (file integrity monitoring). This rule used two filters:
         
         - full_log contains secrets.txt (the file containing the "sensitive" data)
         - syscheck.event is modified
     
     * Rule to detect 3 failed SSH login attempts. This rule used two filters:

         - decoder.name is sshd
         - rule.groups contains authentication_failed
      
   ![Screenshot 2025-02-05 184601](https://github.com/user-attachments/assets/2fd4a4d8-0c93-4fb5-8efa-680d437cec1a)

4. Conduct End-to-End Attacks

   Using Kali Linux as the attacker machine, an end-to-end multi-phase attack was conducted involving a number of tactics.

   Initial Reconnaissance - Nmap scan to scan ports on the Email-Svr machine at 10.0.0.8:

   Nmap scan identified two open ports with their relative service and version:
    * Port 22/tcp: ssh OpenSSH
    * Port 25/tcp: smtp Postfix smtpd

   ![Screenshot 2025-02-05 185634](https://github.com/user-attachments/assets/6481624a-33d2-41a0-a4e3-bc81f1da64cb)

   Since Port 22 (SSH) was open, I attempted to establish an SSH connection. I logged in as "root" and the results show that password authentication is enabled:

   ![Screenshot 2025-02-05 190927](https://github.com/user-attachments/assets/d6f7fb04-6063-470a-8c98-66e83293828d)

   Using Hydra and the rockyou.txt password list, I conducted a brute force attack on the SSH password:

   ![Screenshot 2025-02-05 191212](https://github.com/user-attachments/assets/88a60e08-3501-4065-890e-5a3ad16e4374)

   Hydra identified an account and password (login:root password: november)
   
   ![Screenshot 2025-02-05 191512](https://github.com/user-attachments/assets/747d080b-7330-4a01-9d19-947553b41830)

   Using the obtained credentials from Hydra, I accessed the machine via SSH and conducted further reconnaissance on the machine, identifying the OS, hostname, installed and running services, file structure, configuration files, and          usernames from the /etc/passwd file. This revealed an account named "email-svr" which became the target.

   ![Screenshot 2025-02-20 193110](https://github.com/user-attachments/assets/0ca72aab-a965-41d4-a189-9ba752b60ba7)

   ![Screenshot 2025-02-05 192212](https://github.com/user-attachments/assets/b229d040-6e1e-4ceb-8ef8-92b0c2d0a018)

   ![Screenshot 2025-02-05 192458](https://github.com/user-attachments/assets/439145be-bfb3-4d07-b865-27319585732b)

   After lateral movement to this account, I investigated the contents of the home directory, which further suggested that the machine was functioning as an email server.

   ![Screenshot 2025-02-20 101728](https://github.com/user-attachments/assets/81467c03-9992-46ba-9f16-feaf64e6cee0)

   ![Screenshot 2025-02-20 102123](https://github.com/user-attachments/assets/81fc8c92-ac17-4a01-902b-dad9bbf08ed1)

   After performing reconnaissance, prior emails (on the email-svr) revealed mail previously sent to janed[@]corp.project-x-dc.com.

   I created a web page for harvesting credentials from the user:
   
   ![Screenshot 2025-02-20 103308](https://github.com/user-attachments/assets/7a630a46-3039-4d22-80c7-60c0001712d6)

   I created a phishing email with the embedded link to the "credentials harvesting" page which when the user (janed) entered her credentials, it captured the input into a log file on my Kali attacker machine called (creds.log):

   ![Screenshot 2025-02-20 104341](https://github.com/user-attachments/assets/bbd33827-0b51-41c4-936a-fef92495db2e)

   ![Screenshot 2025-02-20 105102](https://github.com/user-attachments/assets/9c6e2265-7202-4b0c-8f47-d4dfb91af564)

   ![Screenshot 2025-02-20 110350](https://github.com/user-attachments/assets/d9170977-fd11-4925-a2de-4236c847d4c9)

   Using these captured credentials, I SSH into janed Linux workstation (which had been previously identified via the network scan), and conducted Lateral Movement and Privilege Escalation.

   ![Screenshot 2025-02-20 111725](https://github.com/user-attachments/assets/a859aa01-1add-4d20-8148-41c4b27637b4)

   I conducted an Nmap scan of the Windows workstation and port probed 5985 and 5986 "HTTP/HTTPS" - ports for WinRM - remote management tool that allows Administrators to manage and interact with remote computers. WinRM has been heavily      abused in the past to perform lateral movement and privige escalation.

   ![Screenshot 2025-02-20 112918](https://github.com/user-attachments/assets/a7c24cf9-efe0-4f75-a94a-e1e85d4f5c84)

   Using this protocol and NetExec (powerful tool used to compromise services within a network), I conducted a password spray attack focusing on the Windows workstation. This attack revealed the credentials for "Administrator"

   ![Screenshot 2025-02-20 114132](https://github.com/user-attachments/assets/deec07e1-de67-40a6-b3c3-46d2a5508fb7)

   Using "Evil-Winrm" which is an open-source, command tool that installed on Kali which automates brute forcing using the WinRm protocol to attempt to move laterally into the network by compromising domain credentials and gaining a          remote shell into the Windows workstation over WinRM.

   Performed a (nltest / dsgetdc:) which revealed the IP address of the domain controller - very high value target. With further reconaissance by performing an nmap scan of the DC, one particular service that is running that stands out is    3389 - Remote Desktop Protocol (which you are able to sign into the domain controller and remotely administer with UI).

   Using this information, I attempted to access the domain controller using xfreerdp and was successful, resulting in further Lateral Movement.

   Navigation around the file system, I eventually found a folder called "Production Documents" and within the folder a file called "secrets.txt."
   
   ![Screenshot 2025-02-20 120644](https://github.com/user-attachments/assets/ffa35454-dd0c-403f-bfd3-63043258b291)

   ![Screenshot 2025-02-20 121338](https://github.com/user-attachments/assets/41107e20-75d1-4ca2-a6a5-fa5652e30f6a)

   After finding the file called "secrets.txt" residing on the DC, I attempted Data Exfiltration. Using "scp" to copy the files to my Kali and named the file "my_sensitive_file" and was successful.

   ![Screenshot 2025-02-20 153441](https://github.com/user-attachments/assets/59c34ab1-61e4-433d-8034-8d6526a5f0ee)

   ![Screenshot 2025-02-20 125429](https://github.com/user-attachments/assets/f773685c-4d14-4ef1-bb71-8ac7fb89896c)

   # Persistence

   Now that we have effectively pwnd the environment, it's time to ensure we can come back to where we left off and maintain Persistence.

   Persistence refers to attackers maintaing access to a system even after their initial intrusion is discovered and remediated. This ensures the attacker's operations can continue despite interruptions. Common techniques include             installing backdoors, creating rogue accounts, or leveraging legitimate tools for remote access like RDP or VPNs.

   One of the easiest methods of establishing Persistence is by creating a new user account. I created a new user called "project-x-user", added this user to the Administrators group and to the Domain Admins. 

   ![Screenshot 2025-02-20 130815](https://github.com/user-attachments/assets/920c48f5-0151-4797-9a8a-c0e6d9652622)

   ![Screenshot 2025-02-20 131007](https://github.com/user-attachments/assets/9cc81f21-c53b-4f24-a074-7a55aa8e681d)

1. Scheduled Task with Reverse Shell

   In Kali, I created a basic reverse shell script called "reverse.ps1". Using a python webserver to upload the copy from [project-x-attacker] to [project-x-dc], from where the reverse.ps1 script is, I performed the following syntax in       the command line: python -m http.server

   I navigated to the hosted server and downloaded the reverse.ps1 file and moved the file then ran the reverse.ps1 script and you can see "Connected to reverse shell!"

   ![Screenshot 2025-02-20 133421](https://github.com/user-attachments/assets/3bf34682-df93-4e62-9afa-95490b01f21f)

   ![Screenshot 2025-02-20 134939](https://github.com/user-attachments/assets/bd14d8de-73e0-46e4-9f08-0d0636384766)

   ![VirtualBox_ demo-project-x-attacker _20_02_2025_14_12_35](https://github.com/user-attachments/assets/1ca23409-79ff-4eef-9682-3c0b6772c82f)

   As an additional means of Persistence, I ran the Powershell script which created a Scheduled Task daily at 12:00 with the purpose of creating a backdoor.

   ![Screenshot 2025-02-20 135425](https://github.com/user-attachments/assets/39731637-24c4-4140-9fc9-67b744bbb46d)

   The scheduled task was succesfully created:
   
   ![Screenshot 2025-02-20 142107](https://github.com/user-attachments/assets/5856f6e8-cab1-4852-b9c3-7dea355ec6aa)

  # Wazuh Alerts and Logs (Triage as a SOC Analyst)
  
   The 3 rules created earlier in Wazuh successfully detected the relevant activity and alerts were generated:

   ![Screenshot 2025-02-20 143548](https://github.com/user-attachments/assets/777996f1-6520-4915-9051-ad03da799e9b)


   File integrity compromise of "secrets.txt" (Pay attention to syscheck.diff where you can see the altered changes to the secrets.txt file - "Hello Again")

   ![VirtualBox_ demo-project-x-sec-box_20_02_2025_14_37_34](https://github.com/user-attachments/assets/cbffa61e-365d-4313-8f38-1afd9624a6d6)

   ![VirtualBox_ demo-project-x-sec-box_20_02_2025_14_44_06](https://github.com/user-attachments/assets/0e1c0bf4-f737-497f-be8a-e9ed94b7c53e)


   WinRM (Kerberos) logins:

   ![VirtualBox_ demo-project-x-sec-box_20_02_2025_14_52_30](https://github.com/user-attachments/assets/b03fcd78-506e-4b7a-b266-d360a1c5888f)


   Failed SSH login attempts:

   ![VirtualBox_ demo-project-x-sec-box_20_02_2025_14_58_31](https://github.com/user-attachments/assets/c6c70c58-260a-4c70-b3c4-6820010471a1)

   # Conclusion

   I have finished my attack from Reconnaissance, Initial Access, Lateral Movement, Privilege Escalation, Data Exfiltration, and Persistence. This homelab's intention was to serve as a primer for how threat actors approach compromising a     target organization. With various tools, techniques, and procedures (TTP's), threat actors can leverage their skills, open-source knowledge, and now LLMs to achieve their objective.



   





   
   


   




