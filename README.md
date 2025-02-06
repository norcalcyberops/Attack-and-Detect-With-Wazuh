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
 * Microsoft Active Directory: A directory service used for managing and organizing network resources and permissions in a Windows environment.
   - Key Components:
     Authentication: Verifies user identity using credentials like username and password
     Authorization: Grants or denies access to network resources based on permissions
     Centralized Management: Centralizes control over users, computers, and other resources
     
 * Wazuh: An open-source security monitoring platform that provides intrustion detection, log analysis, vulnerability detection, and compliance reporting.
 * Postfix: A popular open-source mail transfer agent (MTA) used for sending and receiving email on Unix-like operating systems.

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
