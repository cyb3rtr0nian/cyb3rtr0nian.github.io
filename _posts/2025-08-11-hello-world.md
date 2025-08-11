---
title: "Nmap Basics"
date: 2025-08-11 00:00:00 +0800
categories: [CTPS]
tags: [Nmap]
---

# Hello World

Hello World, this is my 1st personal blog!

## Nmap
<!-- Replace with your actual image -->


# Command:
nmap <ip> [FLAG]

# Flags #
-PS # Ping Sweep
-PE # ICMP requests, echo
-Pn # Discover all live ports (mainly for Windows)
-sn # Host Discovery (No Port Scan)
-sT # TCP full-connect scan ("Reliable")
-sU # UDP Ping
-sP -PA # TCP-ACK Ping
-sS # SYN-ACK Stealthy and Fast scan (root required)
-PA # ACK Pings
-F  # Fast port scan (top 100 ports)
-n  # No DNS Resolution
-O -n # OS detection
-A -n # Aggressive scan (OS detection, version detection, scripts, traceroute)
-O --osscan-guess # OS guess
-sV # Service Version
-sV --version-intensity 8 # Aggressive service guessing
