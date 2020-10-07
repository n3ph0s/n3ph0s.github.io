---
layout: post
title: How to Think Like a Hacker!
date: 2020-10-07 18:53:34 +0800
categories: technology security
---

![Header Image](/assets/post1/header_image.png)

What do you picture when you think of a hacker? Are they sitting in a dark room with a glow of computer monitors wearing a dark hoodie, listening to fast-paced music and frantically trying to perform multiple tasks? If this is the image you envision, then you aren’t alone as this image has been portrayed so well by Hollywood.

Hackers, as we know it today, e.g. black hat, white hat, have been around since at least November 1963 when the term first appeared in the MIT newspaper, The Tech.

The term hacking is everywhere today and used to describe ways to change what is perceived to be normal behaviour. Terms such as bio-hacking (do it yourself biology experiments), growth hacking (use of creative, low-cost strategies to acquire and retain customers) and even “hacking the happiness molecule.”

So what does this have to do with thinking like a hacker? Before I go into that, we are all creatures of habit, and from the moment we are born, we have behaviours that we develop over time. As we age, these become more complex and nuanced to the point that we operate on autopilot for many tasks, and our life becomes predictable. Our days are well structured as to what time we get up, coffee breaks, lunch and time we stop working and go home. Add into this social media and the “always-connected” lifestyle that we live and it is easy to see how one day starts to look like the next.

So when we look at hackers (computer, bio, growth hackers et al.) the one common trait that I see is they all have an innate curiosity about how things work. It is about how they look at the world and for example, from a cybersecurity perspective when they come across a website or domain; they ask questions, a LOT of them such as:

- What are their subdomains?
- What ports are open?
- Is this a sensitive site?
- Which certs are about to expire?
- Which of these sites is running WordPress?
- Who works at this company?
- Do they have any open S3 buckets?
- Are they serving Databases?

As you can see this continual curiosity for those who are looking for security vulnerabilities to exploit requires that defenders need to think in the same way, which is an adversarial approach.

Given the adversarial nature of computer security which is always in a constant state of flux, the individual actions of the attacker and defender will continually change the state of play. So to learn how to think like a hacker, you need to:

- Understand the tools, techniques and patterns of an attacker.
- What are the goals of an attacker? While in a CTF it may be to get the Domain Admin account, in real life, this may not be the primary target. It could be a database with customer details, sensitive information about employees, source code etc.
- Have intelligence about what information is available about you and your organisation on the public domain (Surface Web, Deep Web, Dark Web).
- Study and appreciate past attacks to understand approaches and the techniques used and then ask and answer honestly what is your risk exposure to these?
- Don’t just use the technology as a tool, but understand how each of the components works together, how it’s configured, what happens if you change values.

There are many excellent resources to understand the tools and techniques used by cybercriminals, and two that I like are MITRE’s Att&CK framework which is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations and The Cyber Kill Chain by Lockheed Martin which is part of their Intelligence Drive Defense model for the identification and prevention of cyber intrusions.

![Cyber Kill Chain](/assets/post1/cyberkillchain.png)

The final skill to develop is “oblique thinking” which is a skill that is finely honed in hackers as there is often no direct path to the objective. The ability is in identifying assumptions that you have made and then finding ways that you can violate these to move you along the path to your target. An example of this is that if you look at a payment processing system, there are several gates that you need to pass before you can complete the process. The developer has designed this sequentially in that you go through them in order, but what if you could skip some steps? How can you test this? What has to be true for this to occur and so on. When you look at this problem and then start breaking it down into known and unknown assumptions, you can begin to see new ways to exploit a system.

By thinking differently, asking questions and looking at things from a different angle, you will start to see areas for improvement and stay one step ahead of the threat.

Happy hacking :)