# Attack-and-Detect-With-Wazuh
# Objective
SOC analysts must possess the essential skills to understand and detect attacks from both offensive and defensive perspectives. In this home lab, I simulated a business network called "ProjecX", introduced vulnerable configurations, performed a multi-phase end-to-end attack, and identified specific activities with detection rules and alerts created in Wazuh. 
This project was created by Grant Collins and can be accessed for free at https://projectsecurity.io/
# Skills Involved
  Computer Networking
  Firewall Configurations
  Windows Active Directory
  Phases of Cyber Attack - Reconnaissance, Initial Access, Lateral Movement, Privilege Escalation, Data Exfiltration, Persistence, Defense Evasion
  Security Monitoring with Security Onion and Wazuh
# End Goal - capture sensitive files and achieve persistence "backdoor" inside the business network so that we can log back in at our discretion. Our attacker is financially motivated, attempting to steal sensitive data. They have identified ProjectX as a target organization to conduct their operations so they can extort and steal sensitive information, perhaps a username, password, and a propietary file.
# Main Steps
1. Build the Enterprise Environment
The first step of the project involved building the enterprise environment using VirtualBox
