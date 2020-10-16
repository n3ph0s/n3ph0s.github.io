---
layout: post
title: Visual Thinking for Cybersecurity
date: 2020-10-16 12:00:41 +0800
categories: technology security
---
![Title Image](/assets/post2/head.png)

You may be thinking from the title of this article, why do I need to think visually? Well, last week, I had an interesting conversation with a Senior Executive about security and that even something as simple as his website could allow for a more extensive compromise and a threat to his business.

I am sure you can imagine how the conversation went as his first response was, “this is not part of the production network,” and in this case, he was right. This statement was the beginning of a discussion about lateral movement from a threat actors perspective and how access can lead to the exploitation of high-value targets. There are so many ways that an attacker can get into a network from simple misconfigurations on a web-facing service to phishing emails.

To demonstrate and make a point, I showed him a copy of BloodHound; it was stored on my machine and loaded with sample data about how the network looked (collected from a low-level authenticated user). Bloodhound provides not only a visual representation of the environment but also paths of attack to a target with the only requirement being you have an AD Authenticated User.

![Bloodhound Visualisation](/assets/post2/bloodhound.png)

Information is in multiple spreadsheets, systems, and the completeness is usually “point in time.” Not having up to date information stored in lists without seeing all the relationships makes it very challenging, if not nearly impossible, to defend a network from an attack. The situation only gets worse the larger the organisation. You then have dedicated teams looking after functions such as Server Team, Network Team, End Users, Backups, AV, etc.

If we look at a Windows Network, users can perform various types of logons (Interactive, Terminal Server, and others). In each of these, the users’ credentials (including SSO equivalents, Kerberos TGT, or NTLM hash) are all exposed to theft if the underlying host is compromised.

There are, of course, other relationships that create security dependencies such as:

- Local admin accounts with a standard password
- File Servers with Logon Scripts or Software Update Servers
- Print Servers
- Certificate Authorities for Smart Cards
- and many others,

The underlying message is that once an attacker gets inside your network, it is just a waiting game for a high-value target to log on to the compromised machine. If you have a Terminal Server in your environment, how many users log in, and are any of those using an administrative account? If so, a password dumper tool such as Mimikatz can give you those credentials that can compromise more machines.

So how do we move to visual thinking as a defender? Visualise your network and implement controls to minimise lateral movement:

- Implement infrastructure partitioning and credential silos to reduce unwanted edges
- Reduce the number of Admins. Implement Just-In-Time/Least Privilege techniques
- Use Two Factor Authentication to mitigate specific edge traversals.
- Ues a robust credential rotation approach in the event a user account is compromised.
- Rethink Forest Trust Relationships

**Key Takeaway**

You have the upper hand when it comes to defending your network as you have the full information about it, whereas an attacker has to build it up piece by piece.

Take a lesson from attackers about how they understand your network and then apply the same principles to identify weaknesses and secure them.
