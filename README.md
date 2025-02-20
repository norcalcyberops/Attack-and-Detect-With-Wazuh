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

   ![Screenshot 2025-02-05 185054](https://github.com/user-attachments/assets/92393d14-367f-4226-920f-ab2ecdbfe3da)

   Nmap scan identified two open ports with their relative service and version:
    * Port 22/tcp: ssh OpenSSH
    * Port 25/tcp: smtp Postfix smtpd

   ![Screenshot 2025-02-05 185634](https://github.com/user-attachments/assets/6481624a-33d2-41a0-a4e3-bc81f1da64cb)

   Since port 22 (SSH) was open, I attempted to establish an SSH connection. I logged in as "root" and the results show that password authentication is enabled:

   ![Screenshot 2025-02-05 190927](https://github.com/user-attachments/assets/d6f7fb04-6063-470a-8c98-66e83293828d)

   Using Hydra and the rockyou.txt password list, I conducted a brute force attack on the SSH password:

   ![Screenshot 2025-02-05 191212](https://github.com/user-attachments/assets/88a60e08-3501-4065-890e-5a3ad16e4374)

   Hydra identified an account and password (login:root password: november)
   
   ![Screenshot 2025-02-05 191512](https://github.com/user-attachments/assets/747d080b-7330-4a01-9d19-947553b41830)

   Using the obtained credentials from Hydra, I accessed the machine via SSH and conducted further reconnaissance on the machine, identifying the OS, hostname, installed and running services, file structure, configuration files, and           usernames from the /etc/passwd file. This revealed an account named "email-svr" which became the target.

   ![Screenshot 2025-02-05 192212](https://github.com/user-attachments/assets/b229d040-6e1e-4ceb-8ef8-92b0c2d0a018)

   ![Screenshot 2025-02-05 192458](https://github.com/user-attachments/assets/439145be-bfb3-4d07-b865-27319585732b)

   After lateral movement to this account, I investigated the contents of the home directory, which further suggested that the machine was functioning as an email server.

   ![Screenshot 2025-02-20 101728](https://github.com/user-attachments/assets/81467c03-9992-46ba-9f16-feaf64e6cee0)

   ![Screenshot 2025-02-20 102123](https://github.com/user-attachments/assets/81fc8c92-ac17-4a01-902b-dad9bbf08ed1)

   After doing enumeration on the emails on the server revealed mail previously sent to janed[@]corp.project-x-dc.com.
   I created a web page for harvesting credentials from the user:
   
   ![Screenshot 2025-02-20 103308](https://github.com/user-attachments/assets/7a630a46-3039-4d22-80c7-60c0001712d6)

   I created a phishing email with the embedded link to the "credentials harvesting" page which when the user enter their credentials it captured the input into a log file on my attacker machine called (creds.log):

   ![Screenshot 2025-02-20 104341](https://github.com/user-attachments/assets/bbd33827-0b51-41c4-936a-fef92495db2e)

   ![Screenshot 2025-02-20 105102](https://github.com/user-attachments/assets/9c6e2265-7202-4b0c-8f47-d4dfb91af564)

   ![Screenshot 2025-02-20 110350](https://github.com/user-attachments/assets/d9170977-fd11-4925-a2de-4236c847d4c9)

   Using these captured credentials, I SSH into janed workstation (which had been previously identified via the network scan), and conducted lateral movement and privilege escalation.

   ![Screenshot 2025-02-20 111725](https://github.com/user-attachments/assets/a859aa01-1add-4d20-8148-41c4b27637b4)

   I conducted a scan of the Windows workstation and port probed 5985 and 5986 "HTTP/HTTPS" which is WinRM - remote management tool that Administrators can sign into and can be exploited.

   ![Screenshot 2025-02-20 112918](https://github.com/user-attachments/assets/a7c24cf9-efe0-4f75-a94a-e1e85d4f5c84)

   Using this protocol and NetExec tool, I conducted a password spray attack focusing on the Windows workstation. This attack revealed the credentials for "Administrator"

   ![Screenshot 2025-02-20 114132](https://github.com/user-attachments/assets/deec07e1-de67-40a6-b3c3-46d2a5508fb7)

   Using "Evil-Winrm" which is an open-source tool that installed on Kali which automates brute forcing using the WinRm protocol to attempt to move laterally into the network by compromising domain credentials and gaining a shell into the    Windows workstation. 

   ![Screenshot 2025-02-20 115231](https://github.com/user-attachments/assets/002182b1-2e44-4ec9-8955-7a5b75dab5a7)

   ![Screenshot 2025-02-20 120644](https://github.com/user-attachments/assets/ffa35454-dd0c-403f-bfd3-63043258b291)

   Performed a (nltest / dsgetdc:) which revealed the IP address of the domain controller. With further reconaissance with an nmap scan of the DC, one particular service that stands out is 3389 - RDP (which you are able to sign into          domain and remotely administer with GUI). Using this information, I attempted to access the domain controller using xfreerdp and was successful, resulting in further lateral movement:

   ![Screenshot 2025-02-20 120434](https://github.com/user-attachments/assets/c9157719-3ed8-4580-9b01-fc192ad33b52)
   
   ![Screenshot 2025-02-20 121338](https://github.com/user-attachments/assets/41107e20-75d1-4ca2-a6a5-fa5652e30f6a)

   

   
   
   



   





   
   


   




