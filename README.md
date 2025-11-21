# Ghost Walk: High-Fidelity Crowd Simulation

> **⚠️ WARNING: READ BEFORE DEPLOYMENT**
>
> **This tool is designed to protect the CROWD, not the OPERATOR.**
>
> If you are a high-value target, **do not carry this device**. If you are operating this device, you are a "beacon" of noise. This tool works by creating statistical noise to invalidate digital surveillance logs.

## 📡 Project Overview

**Ghost Walk** is an ESP32-based firmware designed to generate massive amounts of realistic IEEE 802.11 (WiFi) cover traffic.

Unlike standard traffic generators that produce random, easily filterable noise, Ghost Walk prioritizes **Forensic Validity**. It uses strict "Era Enforcement" to ensure that simulated devices match their hardware profiles. Virtual device mimicking an iPhone 12 behaves exactly like a modern WiFi 6 device, while a virtual legacy IoT device restricts itself to WiFi 4 behaviors.

By deploying multiple units, the system floods the environment with plausible "phantom" identities, rendering MAC address collection, presence detection, and "social graph" analysis statistically unreliable.

---

## 🛡️ Operational Strategy

This is **not** a stealth tool for the user holding it. It is a "chaff" dispenser for the crowd.

* **Obfuscation:** Masks real device signatures by burying them in a swarm of highly specific, generation-accurate fake traffic.
* **Deep Packet Compliance:** Generates structurally valid 802.11 frames with generation-specific Capabilities (HT/VHT/HE) to withstand Deep Packet Inspection (DPI).
* **Behavioral Mimicry:** Simulates the actual connection patterns of human users rather than just flooding beacons.

---

## ⚙️ Technical Features

### 1. Strict Era & Generation Enforcement
The firmware assigns every virtual device a specific generation (`GEN_LEGACY`, `GEN_COMMON`, `GEN_MODERN`) and Platform (`IOS`, `ANDROID`, `IoT`).
* **Hardware Consistency:** A virtual device assigned a Modern Apple OUI will transmit WiFi 6 (802.11ax) capabilities (HE Caps). It will not transmit legacy-only flags that would identify it as a fake.
* **Private Addressing:** Modern virtual devices correctly favor randomized MAC addresses (Locally Administered Bit set) over static OUIs, matching real-world iOS/Android privacy behaviors.

### 2. Interaction Simulation (The "Handshake" Fake)
To defeat passive sniffers that ignore unconnected devices, Ghost Walk includes `ENABLE_INTERACTION_SIM`.
* The swarm occasionally selects a target SSID.
* It performs a full **Authentication -> Association Request -> Encrypted Data Burst** sequence.
* This tricks intrusion detection systems (IDS) into believing the virtual device has established a valid session.

### 3. Smart Noise Floor
To frustrate signal triangulation (RSSI) and fill airtime gaps, the device generates "Smart Noise":
* **Variable TX Power:** Noise is transmitted at randomized, lower power levels (`JUNK_POWER_LEVELS`) to disrupt distance calculations.
* **Hidden Network Mimicry:** Instead of sending obvious wildcards, noise packets mimic "Hidden Network" checks using randomized strings.

### 4. Weighted Identity Distribution
The swarm population is statistically weighted to match a typical modern crowd profile:
* **45% Apple (iOS):** Uses specific Apple Vendor Tags and WiFi 6 (HE) caps where appropriate.
* **25% Samsung (Android):** Uses Android-specific signatures.
* **15% Legacy IoT:** Old HPs, Motorolas, and Nintendos (forced to WiFi 4/Legacy rates).
* **15% Modern Generic:** Intel/Google/Amazon chips (forced to Modern caps).

---

## 🖥️ Hardware & Configuration

### Requirements
* **MCU:** ESP32 (WiFi 6 capable boards preferred for full HE frame fidelity).
* **Display:** TFT Display supported via `TFT_eSPI`.
* **Power:** LiPo battery (external).

### Key Settings (`GhostWalk.ino`)

The system automatically manages resources based on heap availability.

```cpp
// --- CONFIGURATION ---
#define ENABLE_PASSIVE_SCAN true      // Learns local SSIDs to replay them
#define ENABLE_SSID_REPLICATION true  // Mimics networks it sees
#define ENABLE_LIFECYCLE_SIM true     // Rotates devices in/out of the pool
#define ENABLE_INTERACTION_SIM true   // Fakes full connections (Auth/Assoc)

// --- POOL SETTINGS ---
const int STATEFUL_POOL_SIZE = 1000;  // Active devices in RAM
const int DORMANT_POOL_SIZE = 2000;   // Devices "waiting" to arrive
