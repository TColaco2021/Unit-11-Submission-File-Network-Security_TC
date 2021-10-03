# Unit-11-Submission-File-Network-Security_TC

### (Part 1: Review Questions)

### Security Control Types

The concept of defense in depth can be broken down into three different security control types. Identify the security control type of each set  of defense tactics.

1. Walls, bollards, fences, guard dogs, cameras, and lighting are what type of security control?
Answer: Physical

2. Security awareness programs, BYOD policies, and ethical hiring practices are what type of security control?
Answer: Administrative

3. Encryption, biometric fingerprint readers, firewalls, endpoint security, and intrusion detection systems are what type of security control?
Answer: Technical

Intrusion Detection and Attack indicators

1. What's the difference between an IDS and an IPS?

Answer: Intrusion Detection Systems (IDS) analyze network traffic for signatures that match known cyberattacks. Intrusion Prevention Systems (IPS) also analyze packets but can also stop the packet from being delivered based on what kind of attacks it detects — helping stop the attack.

2. What's the difference between an Indicator of Attack and an Indicator of Compromise?

Answer: Indicators of attack (IOA) focus on detecting the intent of what an attacker is trying to accomplish in real time, regardless of the malware or exploit used in an attack. An Indicator of Compromise (IOC) is often described as evidence on a computer that indicates that the security of the network has already been breached.

### The Cyber Kill Chain

Name each of the seven stages for the Cyber Kill chain and provide a brief example of each.

Stage 1: Reconnaissance - The first step of any APT attack is to select a target. Depending on the motive(s) of the APT actor, the victim could be any company or person with information the attacker(s) sees as valuable. Attackers “fingerprint” the target to create a blueprint of IT systems, organizational structure, relationships, or affiliations and search for vulnerabilities—both technical and human— to exploit and breach the network. As large organizations tend to invest in multiple layers of security, this step could take weeks, even months. However, the more knowledge the APT actor acquires on its target, the higher the success rate of breaching the network. Information sources include, DNS registration websites, LinkedIn, Facebook, Twitter, etc.

Stage 2: Weaponization - Next, attackers will re-engineer some core malware to suit their purposes using sophisticated techniques. Depending on the needs and abilities of the attacker, the malware may exploit previously unknown vulnerabilities, aka “zero-day” exploits, or some combination of vulnerabilities, to quietly defeat a network’s defenses. By reengineering the malware, attackers reduce the likelihood of detection by traditional security solutions. This process often involves embedding specially crafted malware into an otherwise benign or legitimate document, such as a press release or contract document, or hosting the malware on a compromised domain.

Stage 3: Delivery - The three most prevalent delivery vectors for weaponized payloads by APT actors, as observed by the US ProTech Computer Incident Response Team (USPT-CIRT) for the years 2005-215, are email attachments, websites, and removable media such as a USB stick.  The transmission and delivery of weaponized bundles to the victim’s targeted environment is the objective but these efforts arrive with some digital fingerprinting.  This stage represents the first and most important opportunity for defenders to block an operation; however, doing so defeats certain key capabilities and other highly prized data.  At this stage we measure of effectiveness of the fractional intrusion attempts that are blocked at the delivery point.

Stage 4: Exploitation - At this stage exploiting a vulnerability to execute code on victim’s system command channel for remote manipulation of victim is the objective.  Here traditional hardening measures add resiliency, but custom defense capabilities are necessary to stop zero-day exploits at this stage.  After the weapon is delivered to victim host, exploitation triggers intruders’ code. Most often, exploitation targets an application or operating system vulnerability, but it could also more simply exploit the users themselves or leverage an operating system feature that auto-executes code. In recent years this has become an area of expertise in the hacking community which is often demonstrated at events such as Blackhat, Defcon and the like.

Stage 5: Installation - At this stage the installation of a remote access Trojan or backdoor on the victim system allows the adversary to maintain persistence inside the environment. Installing malware on the asset requires end-user participation by unknowingly enabling the malicious code. Taking action at this point can be considered critical.  One method to effect this would be to deploy a HIPS (Host-Based Intrusion Prevention System) to alert or block on common installation paths, e.g. NSA Job, RECYCLER. It’s critical to understand if malware requires administrator privileges or only user to execute the objective.  Defenders must understand endpoint process auditing to discover abnormal file creations.  They need to be able to compile time of malware to determine if it is old or new.  Answers to the following questions should be consider mandatory:  How does it last, survive, etc.  Does it use Auto run key, etc.  Does Backdoor need to run to provide access.  

Stage 6: Command and Control - This stage is the defender’s “last best chance” to block the operation: by blocking the Command and Control channel. If adversaries can’t issue commands, defenders can prevent impact. Typically, compromised hosts must beacon outbound to an Internet controller server to establish a Command & Control (aka C2) channel. APT malware especially requires manual interaction rather than conduct activity automatically. Once the C2 channel establishes, intruders effectively have “hands on the keyboard” access inside the target environment.  Let’s remember that seldom is Malware automated, normally this command channel is manual.  The general practice of intruders is:  Email – in, Web = Out.  The trick for them is to have established the control over many work stations in an effort to “exfiltrate” data without setting off any anomalies or other monitoring applications based upon content, quantity, frequency, etc.  Hence, the reason it is essential to have the proper tools in place that can identify, track, observe, stop and destroy these campaigns within your arsenal of capabilities.

Stage 7: Actions on Objectives - The longer an adversary has this level of access, the greater the impact.  Defenders must detect this stage as quickly as possible and deploy tools which will enable them to collect forensic evidence.  One example would include network packet captures, for damage assessment.  Only now, after progressing through the first six phases, can intruders take actions to achieve their original objectives. Typically, the objective of data exfiltration involves collecting, encrypting and extracting information from the victim(s) environment; violations of data integrity or availability are potential objectives as well. Alternatively, and most commonly, the intruder may only desire access to the initial victim box for use as a hop point to compromise additional systems and move laterally inside the network.  Once this stage is identified within an environment, the implementation of prepared reaction plans must be initiated.  At a minimum, the plan should include a comprehensive communication plan, detailed evidence must be elevated to the highest ranking official or governing Board, the deployment of end-point security tools to block data loss and preparation for briefing a CIRT Team.  Having these resources well established in advance is a “MUST” in today’s quickly evolving landscape of cybersecurity threats.

### Snort Rule Analysis

Use the Snort rule to answer the following questions:

### Snort Rule #1

alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

1. Break down the Sort Rule header and explain what is happening.

Answer: This sort rule header indicates an alert has been set up to inform the user of all inbound TCP traffic from ports 5800 to 5820.

2. What stage of the Cyber Kill Chain does this alert violate?

Answer: Reconnaissance.

3. What kind of attack is indicated?

Answer: A potential VNC scan. Virtual Network Computing (VNC) is a graphical desktop-sharing system that uses the Remote Frame Buffer protocol (RFB) to remotely control another computer. It transmits the keyboard and mouse input from one computer to another, relaying the graphical-screen updates, over a network. Hackers may search these ports for an available connection without proper authentication established in order to enter a network maliciously.

### Snort Rule #2

alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)

1. Break down the Sort Rule header and explain what is happening.

Answer: This sort rule header indicates an alert has been set up to inform the user of all inbound TCP traffic on port 80, HTTP.

2. What layer of the Defense in Depth model does this alert violate?

Answer: Perimeter.

3. What kind of attack is indicated?

Answer: POLICY PE EXE or DLL Windows file download HTTP.

### Snort Rule #3

- Your turn! Write a Snort rule that alerts when traffic is detected inbound on port 4444 to the local network on any port. Be sure to include the `msg` in the Rule Option.
Answer: alert tcp $EXTERNAL_NET any -> $HOME_NET 4400 (msg: "ET Possible Trojan or CrackDown”

### Part 2: "Drop Zone" Lab

Log into the Azure `firewalld` machine

Log in using the following credentials:
- Username: `sysadmin`
- Password: `cybersecurity`

Uninstall `ufw`

Before getting started, you should verify that you do not have any instances of `ufw` running. This will avoid conflicts with your `firewalld` service. This also ensures that `firewalld` will be your default firewall.

- Run the command that removes any running instance of `ufw`.

$ sudo apt -y remove ufw

Enable and start `firewalld`:

By default, this service should be running. If not, then run the following commands:

- Run the commands that enable and start `firewalld` upon boots and reboots.

$ sudo systemctl enable firewalld
$ sudo systemctl start firewalld	

Note: This will ensure that `firewalld` remains active after each reboot.

Confirm that the service is running:

- Run the command that checks if the `firewalld` service is up and running.

$ sudo firewall-cmd –state

List all firewall rules currently configured:

Next, lists all currently configured firewall rules. This will give you a good idea of what's currently configured and save you time in the long run by not doing double work.

- Run the command that lists all currently configured firewall rules:

$ sudo firewall-cmd --list-all

- Take note of what Zones and settings are configured. You many need to remove unneeded services and settings.
List all supported service types that can be enabled:

- Run the command that lists all currently supported services to see if the service you need is available

$ sudo firewalld-cmd --get-services

- We can see that the `Home` and `Drop` Zones are created by default.
Zone Views

- Run the command that lists all currently configured zones.

$ sudo firewall-cmd --lit-all-zones

- We can see that the `Public` and `Drop` Zones are created by default. Therefore, we will need to create Zones for `Web`, `Sales`, and `Mail`.
Create Zones for `Web`, `Sales` and `Mail`:

- Run the commands that create Web, Sales and Mail zones.

$ sudo firewall-cmd --permanent --new-zone=web
$ sudo firewall-cmd --permanent --new-zone=mail
$ sudo firewall-cmd --permanent --new-zone=sales

Set the zones to their designated interfaces:

- Run the commands that sets your `eth` interfaces to your zones.

$ sudo firewall-cmd --zone=public --change-interface=eth0
$ sudo firewall-cmd --zone=mail --change-interface=eth0
$ sudo firewall-cmd --zone=sales --change-interface=eth0
$ sudo firewall-cmd --zone=web --change-interface=eth0

Add services to the active zones:

- Run the commands that add services to the **public** zone, the **web** zone, the **sales** zone, and the **mail** zone.

- Public:

$ sudo firewall-cmd --zone=public --add-service=smtp
$ sudo firewall-cmd --zone=public --add-service=http
$ sudo firewall-cmd --zone=public --add-service=https
$ sudo firewall-cmd --zone=public --add-service=pop3

- Web:

$ sudo firewall-cmd --zone=web --add-service=http

- Sales

$ sudo firewall-cmd --zone=sales --add-service=https

- Mail

$ sudo firewall-cmd --zone=mail --add-service=smtp
$ sudo firewall-cmd --zone=mail --add-service=pop3

- What is the status of `http`, `https`, `smtp` and `pop3`? active 

Add your adversaries to the Drop Zone.
- Run the command that will add all current and any future blacklisted IPs to the Drop Zone.

$ sudo firewall-cmd --permanent --zone=drop --add-source=ipset:blacklist

Make rules permanent then reload them:

It's good practice to ensure that your `firewalld` installation remains nailed up and retains its services across reboots. This ensure that the network remains secured after unplanned outages such as power failures.

- Run the command that reloads the `firewalld` configurations and writes it to memory:

$ sudo firewall-cmd—reload 

View active Zones

Now, we'll want to provide truncated listings of all currently **active** zones. This a good time to verify your zone settings.

- Run the command that displays all zone services.

$ sudo firewall-cmd --get-active-zones

Block an IP address

- Use a rich-rule that blocks the IP address `138.138.0.3`.

$ sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="138.138.0.3" reject' 

Block Ping/ICMP Requests

Harden your network against `ping` scans by blocking `icmp ehco` replies.

- Run the command that blocks `pings` and `icmp` requests in your `public` zone.

$ sudo firewall-cmd --zone=public --add-icmp-block=echo-reply --add-icmp-block=echo-request 

Rule Check

Now that you've set up your brand new `firewalld` installation, it's time to verify that all of the settings have taken effect.

- Run the command that lists all  of the rule settings. Do one command at a time for each zone.

$ sudo firewall-cmd --zone=public --list-all
$ sudo firewall-cmd --zone=sales --list-all
$ sudo firewall-cmd --zone=mail --list-all
$ sudo firewall-cmd --zone=web --list-all
$ sudo firewall-cmd --permanent --zone=drop --list-all 

- Are all of our rules in place? If not, then go back and make the necessary modifications before checking again.

Congratulations! You have successfully configured and deployed a fully comprehensive `firewalld` installation. 

### Part 3: IDS, IPS, DiD and Firewalls

Now, we will work on another lab. Before you start, complete the following review questions.

### IDS vs. IPS Systems

1. Name and define two ways an IDS connects to a network.

Answer 1: Network TAPs are a purpose-built hardware device that sits in a network segment, between two appliances (router, switch or firewall), and allows you to access and monitor the network traffic. TAPs transmit both the send and receive data streams simultaneously on separate dedicated channels, ensuring all data arrives at the monitoring or security device in real time.

Answer 2: Port Mirroring also known as SPAN (Switch Port Analyzer), are designated ports on a network appliance (switch), that are programmed to send a copy of network packets seen on one port (or an entire VLAN) to another port, where the packets can be analyzed.

2. Describe how an IPS connects to a network.

Answer: The IPS often sits directly behind the firewall and is placed inline (in the direct communication path between source and destination), actively analyzing and taking automated actions on all traffic flows that enter the network.

3. What type of IDS compares patterns of traffic to predefined signatures and is unable to detect Zero-Day attacks?

Answer: A signature-based IDS looks for specific, predefined patterns signatures) in network traffic. It compares the network traffic to a database of known attacks and triggers an alarm or prevents communication if a match is found.

4. Which type of IDS is beneficial for detecting all suspicious traffic that deviates from the well-known baseline and is excellent at detecting when an attacker probes or sweeps a network?

Answer: Anomaly or profile-based IDS analyzes computer activity and network traffic looking for anomalies. If an anomaly is found, an alarm is triggered. Because this type of detection is looking for any activity or traffic that isn’t normal, the security administrator must first define what is normal activity or traffic. Security administrators can define normal activity by creating user group profiles. 

### Defense in Depth 

1. For each of the following scenarios, provide the layer of Defense in Depth that applies:

1.  A criminal hacker tailgates an employee through an exterior door into a secured facility, explaining that they forgot their badge at home.

Answer: Physical	 

2. A zero-day goes undetected by antivirus software. 

Answer: Application

3. A criminal successfully gains access to HR’s database.

Answer: Data

4. A criminal hacker exploits a vulnerability within an operating system.

Answer: Host

5. A hacktivist organization successfully performs a DDoS attack, taking down a government website.

Answer: Network

6. Data is classified at the wrong classification level.

Answer: Policy, procedures, & awareness.

7. A state sponsored hacker group successfully firewalked an organization to produce a list of active services on an email server.

Answer: Perimeter.

8. Name one method of protecting data-at-rest from being readable on a hard drive.

Answer: Encrypting hard drives is one of the best ways to ensure the security of data at rest.

9. Name one method to protect data-in-transit.

Answer: Hiding your IP address and encrypting the data you send and receive through VPN tunneling is one powerful combination to help keep your online data-in-transit more secure.

10. What technology could provide law enforcement with the ability to track and recover a stolen laptop.

Answer: Police can track laptops through the installation of hardware or software that will help identify and locate the laptop if stolen. These components (which can include GPS tracking chips or monitoring software) are installed on the laptop before purchase. 

11. How could you prevent an attacker from booting a stolen laptop using an external hard drive?

Answer: Add a firmware password for the BIOS.

### Firewall Architectures and Methodologies

1. Which type of firewall verifies the three-way TCP handshake? TCP handshake checks are designed to ensure that session packets are from legitimate sources.

Answer: A simplistic firewall type that is meant to quickly and easily approve or deny traffic without consuming significant computing resources, circuit-level gateways work by verifying the transmission control protocol (TCP) handshake. This TCP handshake check is designed to make sure that the session the packet is from is legitimate.

2. Which type of firewall considers the connection as a whole? Meaning, instead of looking at only individual packets, these firewalls look at whole streams of packets at one time.

Answer: A stateful firewall is a firewall that monitors the full state of active network connections. This means that stateful firewalls are constantly analyzing the complete context of traffic and data packets, seeking entry to a network rather than discrete traffic and data packets in isolation.

3. Which type of firewall intercepts all traffic prior to being forwarded to its destination. In a sense, these firewalls act on behalf of the recipient by ensuring the traffic is safe prior to forwarding it?

Answer: A proxy firewall is the most secure form of firewall, which filters messages at the application layer to protect network resources. A proxy firewall, also known as an application firewall or a gateway firewall, limits the applications that a network can support, which increases security levels but can affect functionality and speed.

4. Which type of firewall examines data within a packet as it progresses through a network interface by examining source and destination IP address, port number, and packet type- all without opening the packet to inspect its contents?

Answer: Packet Filter or Stateless Firewall controls the network access by analyzing the outgoing and incoming packets. It lets a packet pass or block its way by comparing it with pre-established criteria like allowed IP addresses, packet type, port number, etc.
5. Which type of firewall filters based solely on source and destination MAC address?

Answer: MAC layer firewalls are designed to operate at the media access control layer of the OSI network mode. This gives these firewalls the ability to consider the specific host computer‘s identity in its filtering decisions. Using this approach, the MAC addresses of specific host computers are linked to ACL entries that identify the specific types of packets that can be sent to each host, and all other traffic is blocked.

### Bonus Lab: "Green Eggs & SPAM"

In this activity, you will target spam, uncover its whereabouts, and attempt to discover the intent of the attacker. 

You will assume the role of a Jr. Security administrator working for the Department of Technology for the State of California. As a junior administrator, your primary role is to perform the initial triage of alert data: the initial investigation and analysis followed by an escalation of high priority alerts to senior incident handlers for further review. You will work as part of a Computer and Incident Response Team (CIRT), responsible for compiling **Threat Intelligence** as part of your incident report.

Threat Intelligence Card

Note: Log into the Security Onion VM and use the following **Indicator of Attack** to complete this portion of the homework.

Locate the following Indicator of Attack in Sguil based off of the following:

- **Source IP/Port**: `188.124.9.56:80`
- **Destination Address/Port**: `192.168.3.35:1035`
- **Event Message**: `ET TROJAN JS/Nemucod.M.gen downloading EXE payload`

Answer the following:

1. What was the indicator of an attack?

- Hint: What do the details of the reveal?

Answer: Trojan Attack downloading EXE or DLL

2. What was the adversarial motivation (purpose of attack)?

Answer: Double layer Malware attack designed to trick victimes into believing they owe money for services rendered (fake PDF invoice_.

3. Describe observations and indicators that may be related to the perpetrators of the intrusion. Categorize your insights according to the appropriate stage of the cyber kill chain, as structured in the following table.
| TTP | Example | Findings |
| --- | --- | --- |

| **Reconnaissance** |  How did the attackers locate the victim? | Phishing campaign specifically aimed at Italian victims. 

| **Weaponization** |  What was it that was downloaded?|ZIP file containing Javascript which causes web browser to open and execute Javascript.

| **Delivery** |	How was it downloaded?| SPAM email

| **Exploitation** |  What does the exploit do?| It will use three Activex controls to save an executable file to the temp folder and in turn open a fake PDF invoice.

| **Installation** | How is the exploit installed?|Via Javascript executable and with a DLL download.

| **Command & Control (C2)** | How does the attacker gain control of the remote machine?| Botnet is established after victim’s computer is rebooted and malware activates.

| **Actions on Objectives** | What does the software that the attacker sent do to complete it's tasks?| Nemucod is used to download a Trojan downloader called Fareit or Pony Downloader which in turn downloads other executable files containing Gozi Infostealer. 

4. What are your recommended mitigation strategies? 

Answer: Initiate email scanning (S/MIME) and teaching best practices to not open any zip files from unknown senders.

5. List your third-party references.

Answer: www.certego.net

