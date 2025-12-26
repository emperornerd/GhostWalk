# Ghost Walk: High-Fidelity Crowd Simulation

> **⚠️ WARNING: READ BEFORE DEPLOYMENT**
>
> **This tool is designed to protect the CROWD, not the OPERATOR.**
>
> If you are a high-value target, **do not carry this device**. If you are operating this device, you are a "beacon" of noise. This tool works by creating statistical noise to invalidate digital surveillance logs.

## 📡 Project Overview

[cite_start]**Ghost Walk** is an ESP32-based firmware designed to generate massive amounts of realistic IEEE 802.11 (WiFi) cover traffic[cite: 1].

[cite_start]**New Capabilities:** The project now supports **Dual-Band (2.4GHz / 5GHz)** operation on ESP32-C5 hardware, featuring "Smart Mesh Isolation" for forensic hardening[cite: 1].

Unlike standard traffic generators that produce random, easily filterable noise, Ghost Walk prioritizes **Forensic Validity**. [cite_start]It uses strict "Era Enforcement" to ensure that simulated devices match their hardware profiles[cite: 1]. [cite_start]A virtual device mimicking an iPhone 12 behaves exactly like a modern WiFi 6 device, while a virtual legacy IoT device restricts itself to WiFi 4 behaviors[cite: 22].

By deploying multiple units, the system floods the environment with plausible "phantom" identities, rendering MAC address collection, presence detection, and "social graph" analysis statistically unreliable.

---

## 🛡️ Operational Strategy

This is **not** a stealth tool for the user holding it. It is a "chaff" dispenser for the crowd.

* **Obfuscation:** Masks real device signatures by burying them in a swarm of highly specific, generation-accurate fake traffic.
* [cite_start]**Deep Packet Compliance:** Generates structurally valid 802.11 frames with generation-specific Capabilities (HT/VHT/HE) to withstand Deep Packet Inspection (DPI)[cite: 45, 46].
* **Behavioral Mimicry:** Simulates the actual connection patterns of human users rather than just flooding beacons.

---

## ⚙️ Technical Features

### 1. Interleaved Dual-Band Hopping
[cite_start]On ESP32-C5 hardware, the system utilizes both 2.4GHz and 5GHz bands[cite: 1].
* [cite_start]**5GHz Coverage:** Broadcasts on channels 36–165 using appropriate VHT (Very High Throughput) tags[cite: 21, 171].
* [cite_start]**Band Fidelity:** Legacy virtual devices stay on 2.4GHz, while Modern devices hop between bands naturally[cite: 279].

### 2. Smart Mesh Isolation
[cite_start]Includes a "Best-Effort" Mesh Relay designed for high-density environments[cite: 1].
* [cite_start]**Smart Filtering:** The relay includes logic to ignore smartphones (Apple/Samsung) and valid mesh nodes, preventing the device from accidentally relaying AirDrop or personal hotspot traffic [cite: 228-231].
* [cite_start]**Decay Timers:** Mesh data is cached but decays after 10 minutes to prevent "ghost echoes" of devices that have left the area[cite: 13].
* [cite_start]**Dynamic Intervals:** Switches between fast checks (4000ms) when active and slow checks (10000ms) when in standby[cite: 8, 9].

### 3. Strict Era & Generation Enforcement
[cite_start]The firmware assigns every virtual device a specific generation (`GEN_LEGACY`, `GEN_COMMON`, `GEN_MODERN`) and Platform (`IOS`, `ANDROID`, `IoT`)[cite: 22, 23].
* **Hardware Consistency:** A virtual device assigned a Modern Apple OUI will transmit WiFi 6 (802.11ax) capabilities (HE Caps). [cite_start]It will not transmit legacy-only flags that would identify it as a fake[cite: 136, 160].
* [cite_start]**Private Addressing:** Modern virtual devices correctly favor randomized MAC addresses (Locally Administered Bit set) over static OUIs [cite: 90-91].

### 4. Interaction Simulation (The "Handshake" Fake)
[cite_start]To defeat passive sniffers that ignore unconnected devices, Ghost Walk includes `ENABLE_INTERACTION_SIM`[cite: 7].
* [cite_start]The swarm occasionally selects a target SSID[cite: 280].
* [cite_start]It performs a full **Authentication -> Association Request -> Encrypted Data Burst** sequence [cite: 281-285].
* This tricks intrusion detection systems (IDS) into believing the virtual device has established a valid session.

### 5. Weighted Identity Distribution
[cite_start]The swarm population is statistically weighted to match a typical modern crowd profile [cite: 83-89]:
* **40% Apple (iOS):** Uses specific Apple Vendor Tags and WiFi 6 (HE) caps where appropriate.
* **35% Samsung (Android):** Uses Android-specific signatures.
* **7% Legacy IoT:** Old HPs, Motorolas, and Nintendos (forced to WiFi 4/Legacy rates).
* **18% Modern Generic:** Intel/Google/Amazon chips (forced to Modern caps).

---

## 🖥️ Hardware & Configuration

### Supported Hardware

| Hardware | Band Support | Display Mode | Notes |
| :--- | :--- | :--- | :--- |
| **Standard ESP32** | 2.4GHz Only | TFT Enabled | [cite_start]Optimized for "Cheap Yellow Display" (CYD)[cite: 173]. |
| **ESP32-C5** | Dual Band (2.4/5GHz) | Headless | TFT disabled to prevent SPI conflicts. [cite_start]Output via Serial[cite: 1, 4]. |

### Key Settings (`GhostWalk.ino`)

The system automatically manages resources based on heap availability.

```cpp
// --- CONFIGURATION ---
[cite_start]#define ENABLE_PASSIVE_SCAN true      // Learns local SSIDs to replay them [cite: 7]
[cite_start]#define ENABLE_SSID_REPLICATION true  // Mimics networks it sees [cite: 7]
[cite_start]#define ENABLE_LIFECYCLE_SIM true     // Rotates devices in/out of the pool [cite: 7]
[cite_start]#define ENABLE_BEACON_EMULATION true  // Transmits Beacon frames [cite: 7]
[cite_start]#define ENABLE_INTERACTION_SIM true   // Fakes full connections (Auth/Assoc) [cite: 7]

// --- MESH RELAY CONFIGURATION ---
[cite_start]#define ENABLE_MESH_RELAY true        // Master switch for mesh functionality [cite: 8]
[cite_start]#define MESH_CHANNEL 1                // Channel dedicated to mesh relay ops [cite: 8]

// --- POOL SETTINGS ---
const int TARGET_ACTIVE_POOL = 1500;   [cite_start]// Active devices in RAM [cite: 15]
const int TARGET_DORMANT_POOL = 3000;  [cite_start]// Devices "waiting" to arrive [cite: 15]
