# KQL Threat Hunting and Incident Response

Welcome to the KQL (Kusto Query Language) Hunting and Incident Response repository. This repository contains a collection of queries designed for detecting, hunting, and responding to various security incidents. The queries are organized into different categories to facilitate easy navigation and usage.

## Table of Contents

1. [Detections](#detections)
2. [Digital Forensics](#digital-forensics)
3. [Hunting by Entity](#hunting-by-entity)
   - [Device](#device)
   - [Email](#email)
   - [User](#user)
4. [Operations](#operations)

## Detections

This directory contains KQL queries designed to detect various suspicious and malicious activities. The detections cover a wide range of attack techniques, including command execution, file activity, registry changes, and network communications, among others.

## Digital Forensics

This directory includes scripts and output files for performing comprehensive digital forensics. These tools help in analyzing browser activities and operating system artifacts to uncover potential security incidents.

## Hunting by Entity

This section is organized by different entities, providing queries to hunt for specific activities related to each entity.

### Device

Queries in this section focus on monitoring and analyzing device-specific activities, including logons, file downloads, network communications, and USB events.

### Email

This section contains queries to monitor and detect suspicious email activities, such as the presence of non-standard characters, external domain interactions, forwarding rules, and email exfiltration attempts.

### User

User-focused queries in this section help monitor Azure Active Directory risk events, group membership changes, password activities, sign-in attempts, and user web search histories.

## Operations

The Operations directory includes queries related to operational tasks such as identifying similar incidents and tuning analytics for improved detection and response capabilities.
