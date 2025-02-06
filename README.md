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
 
 * Wazuh: An open-source security monitoring platform that provides intrustion detection, log analysis, vulnerability detection, and compliance reporting.
   A dedicated security server is critical for ensuring the performance, security, and scalability of your monitored analysis stack. Here's why:
    - Isolation: Running resource-intensive tools on a dedicated server prevents performance degradation caused by workloads on shared resources. Each application demands significant CPU, RAM, and disk I/O to function efficiently.
    - Security Context: Security tools process sensitive data, including logs and vulnerability scans. A dedicated server isolates sensitive data from unrelated systems.
    - Centralized Management: Simplifies monitoring and management, providing a single point for handling logs, alerts, and vulnerability data.

  (We will be using Wazuh as our open-source security tool to monitor and detect our simulated "attack")
   
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

   ![Screenshot 2025-02-05 193032](https://github.com/user-attachments/assets/d4299e1d-57c0-4a6d-9ec2-beac3463f241)

   
   


   




