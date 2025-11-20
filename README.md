# Ghost Walk (Privacy & Anonymity Shield)

> **⚠️ WARNING: READ BEFORE DEPLOYMENT**
>
> **This tool is designed to protect the CROWD, not the OPERATOR.**
>
> If you are a high-value target, **do not carry this device**. If you are operating this device, you are a "beacon" of noise. This tool works by creating statistical noise to invalidate digital surveillance logs.

## 📡 Project Overview

**Ghost Walk** is an ESP32-based firmware designed to generate massive amounts of realistic IEEE 802.11 (WiFi) cover traffic. Unlike standard "deauthers" or "spammers" which generate easily filterable random noise, Ghost Walk mimics human behavior to poison the datasets of commercial and surveillance analytics tools.

By deploying 20-50 of these units in a specific area, the system floods the environment with ~1.1 million realistic "phantom" identities. This renders MAC address collection, presence detection, and "social graph" analysis statistically useless, creating plausible deniability for every legitimate person in the vicinity.

### Purpose
* **Obfuscation:** Masks real device signatures by burying them in a swarm of fake traffic.
* **Dataset Poisoning:** Increases the "cost of conviction" by corrupting the digital data collected at a location.
* **Non-Interference:** Strictly avoids RF jamming; operates using standard 802.11 headers and timing.

---

## 🛡️ The Strategy: "Needle in a Pile of Needles"

This is **not** a stealth tool for the user holding it. It is a "chaff" dispenser for the crowd.

### Who is this for?
* **The Crowd ("Normies"):** Passive participants in demonstrations or large gatherings who wish to avoid automated inclusion in dragnet surveillance databases.
* **Privacy Researchers:** Testing the resilience of retail analytics and tracking hardware against obfuscated datasets.

### Who is this NOT for?
* **High-Value Targets:** If you are specifically wanted, this device does not hide you. It makes you the center of an anomaly.
* **Lone Operators:** A single unit is easily triangulated. This system relies on **volume** (20+ units) to prevent triangulation via RSSI clustering.

---

## ⚙️ Technical Features

Ghost Walk goes beyond random MAC generation by implementing "Behavioral Mimicry":

### 1. Stateful Swarm Emulation
Instead of spewing random packets, the system maintains a `VirtualDevice` struct for up to 1,000 active virtual identities simultaneously.
* **Persistence:** Virtual devices maintain `sequenceNumber` continuity, making them look like established sessions rather than glitchy noise.
* **Lifecycle Management:** Devices don't just "appear." They rotate between an `activeSwarm` and a `dormantSwarm`, simulating people naturally walking in and out of range (Arrival/Departure simulation).

### 2. Vendor Profile Mimicry (OUI)
Security filters often ignore "random" unassigned MAC addresses. Ghost Walk utilizes a database of real OUI prefixes to impersonate specific hardware:
* **Apple (iOS):** Mimics iPhone probe request behavior and specific data rates.
* **Samsung/Android:** Mimics generic Android signatures.
* **Learning Mode:** Can passively listen to the environment to learn and replicate local vendors.

### 3. Realistic Traffic Patterning
* **Sequence Gapping:** Intentionally skips sequence numbers to simulate realistic packet loss (`ENABLE_SEQUENCE_GAPS`).
* **Probe Requests:** Generates directed and broadcast probe requests to flood "Passive Sniffers".
* **Beacon Emulation:** (Optional) Emulates Access Points to confuse WiFi scanners.

---

## 🖥️ Hardware & Configuration

### Requirements
* **MCU:** ESP32 (WROOM or WROVER recommended).
* **Display:** TFT Display (e.g., TTGO T-Display) for runtime metrics.
* **Power:** LiPo battery (external).

### Key Settings (`GhostWalk.ino`)
Adjust these based on crowd size and density:

```cpp
// Total virtual devices per unit (Standard: 3000)
const int STATEFUL_POOL_SIZE = 1000; 
const int DORMANT_POOL_SIZE = 2000;

// How "fast" the virtual crowd churns (in milliseconds)
const int LIFECYCLE_INTERVAL_MS = 3500; 

// Toggle "Learning" mode (Listen before speaking)
#define ENABLE_PASSIVE_SCAN true
