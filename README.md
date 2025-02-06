# Attack and Detect With Wazuh
# Objective
SOC analysts must possess the essential skills to understand and detect attacks from both offensive and defensive perspectives. In this home lab, I simulated a business network called "ProjectX", introduced vulnerable configurations, performed a multi-phase end-to-end attack, and identified specific activities with detection rules and alerts created in Wazuh. 
This project was created by Grant Collins and can be accessed for free at https://projectsecurity.io/
# Skills Involved
  Computer Networking, Firewall Configurations, Windows Active Directory, Phases of Cyber Attack - Reconnaissance, Initial Access, Lateral Movement, Privilege Escalation, Data Exfiltration,       Persistence, Defense Evasion, Security Monitoring with Security Onion and Wazuh
# Skill Development
  Allows hands-on experience with tools like SIEMS, vulnerability scanners, and packet analyzers in a network context.
  Simulating incidents such as malware outbreaks or unauthorized access provides valuable experience in real-time response.
# End Goal
  Capture sensitive files and achieve persistence "backdoor" inside the business network so that we can log back in at our discretion. Our attacker is financially motivated, attempting to steal   sensitive data. They have identified ProjectX as a target organization to conduct their operations so they can extort and steal sensitive information, perhaps a username, password, and a        propietary file.
# Main Steps
1. Build an Enterprise Environment.
  a. The first step of the project involved building the enterprise environment using VirtualBox
![Screenshot 2025-02-05 173214](https://github.com/user-attachments/assets/c947abc2-27de-4d0b-b80b-503681dfdf4c)

  As shown in the topology above, the Email Server and three PC's were connected to the Active Directory domain controller.
