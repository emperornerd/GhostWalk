# Ghost Walk: High-Fidelity Crowd Simulation

> **⚠️ WARNING: READ BEFORE DEPLOYMENT**
>
> **This tool is designed to protect the CROWD, not the OPERATOR.**
>
> If you are a high-value target, **do not carry this device**. If you are operating this device, you are a "beacon" of noise. This tool works by creating statistical noise to invalidate digital surveillance logs.

## 📡 Project Overview

**Ghost Walk** is an ESP32-based firmware designed to generate massive amounts of realistic IEEE 802.11 (WiFi) cover traffic.

**New Capabilities:** The project now supports **Dual-Band (2.4GHz / 5GHz)** operation on ESP32-C5 hardware, and forensic hardening.

Unlike standard traffic generators that produce random, easily filterable noise, Ghost Walk prioritizes **Forensic Validity**. It uses strict "Era Enforcement" to ensure that simulated devices match their hardware profiles. A virtual device mimicking an iPhone 12 behaves exactly like a modern WiFi 6 device, while a virtual legacy IoT device restricts itself to WiFi 4 behaviors.

By deploying multiple units, the system floods the environment with plausible "phantom" identities, rendering MAC address collection, presence detection, and "social graph" analysis statistically unreliable.

---

## 🛡️ Operational Strategy

This is **not** a stealth tool for the user holding it. It is a "chaff" dispenser for the crowd.

* **Obfuscation:** Masks real device signatures by burying them in a swarm of highly specific, generation-accurate fake traffic.
* **Deep Packet Compliance:** Generates structurally valid 802.11 frames with generation-specific Capabilities (HT/VHT/HE) to withstand Deep Packet Inspection (DPI).
* **Behavioral Mimicry:** Simulates the actual connection patterns of human users rather than just flooding beacons.

---

## ⚙️ Technical Features

### 1. Interleaved Dual-Band Hopping
On ESP32-C5 hardware, the system utilizes both 2.4GHz and 5GHz bands.
* **5GHz Coverage:** Broadcasts on channels 36–165 using appropriate VHT (Very High Throughput) tags.
* **Band Fidelity:** Legacy virtual devices stay on 2.4GHz, while Modern devices hop between bands naturally.

### 2. Support for related protest mesh project
Includes a "Best-Effort" Mesh Relay designed for expanding mesh range or filling out thin mesh areas.
* **Integration:** This relay is designed to support the [esp32mesh](https://github.com/emperornerd/esp32mesh) project. If a compatible mesh is not detected, it functions as a stand-alone product without mesh relay.
* **Smart Filtering:** The relay includes logic to ignore connected smartphones (eg. WPA2, WPA3 connections), preventing the device from accidentally relaying AirDrop or personal hotspot traffic.
* **Decay Timers:** Mesh data is cached but decays after 10 minutes to prevent "ghost echoes" of devices that have left the area.
* **Dynamic Intervals:** Switches between fast checks when active and slow checks when in standby.

### 3. Strict Era & Generation Enforcement
The firmware assigns every virtual device a specific generation (`GEN_LEGACY`, `GEN_COMMON`, `GEN_MODERN`) and Platform (`IOS`, `ANDROID`, `IoT`).
* **Hardware Consistency:** A virtual device assigned a Modern Apple OUI will transmit WiFi 6 (802.11ax) capabilities (HE Caps). It will not transmit legacy-only flags that would identify it as a fake.
* **Private Addressing:** Modern virtual devices correctly favor randomized MAC addresses (Locally Administered Bit set) over static OUIs.

### 4. Interaction Simulation (The "Handshake" Fake)
To defeat passive sniffers that ignore unconnected devices, Ghost Walk includes `ENABLE_INTERACTION_SIM`.
* The swarm occasionally selects a target SSID.
* It performs a full **Authentication -> Association Request -> Encrypted Data Burst** sequence.
* This tricks intrusion detection systems (IDS) into believing the virtual device has established a valid session.

### 5. Weighted Identity Distribution
The swarm population is statistically weighted to match a typical modern crowd profile:
* **40% Apple (iOS):** Uses specific Apple Vendor Tags and WiFi 6 (HE) caps where appropriate.
* **35% Samsung (Android):** Uses Android-specific signatures.
* **7% Legacy IoT:** Old HPs, Motorolas, and Nintendos (forced to WiFi 4/Legacy rates).
* **18% Modern Generic:** Intel/Google/Amazon chips (forced to Modern caps).

---

## 🖥️ Hardware & Configuration

### Supported Hardware

| Hardware | Band Support | Display Mode | Notes |
| :--- | :--- | :--- | :--- |
| **Standard ESP32** | 2.4GHz Only | TFT Enabled | Optimized for "Cheap Yellow Display" (CYD). |
| **ESP32-C5** | Dual Band (2.4/5GHz) | Headless | TFT disabled to prevent SPI conflicts. Output via Serial. |

### Key Settings (`GhostWalk.ino`)

The system automatically manages resources based on heap availability.

```cpp
// --- CONFIGURATION ---
#define ENABLE_PASSIVE_SCAN true      // Learns local SSIDs to replay them
#define ENABLE_SSID_REPLICATION true  // Mimics networks it sees
#define ENABLE_LIFECYCLE_SIM true     // Rotates devices in/out of the pool
#define ENABLE_BEACON_EMULATION true  // Transmits Beacon frames
#define ENABLE_INTERACTION_SIM true   // Fakes full connections (Auth/Assoc)

// --- MESH RELAY CONFIGURATION ---
#define ENABLE_MESH_RELAY true        // Master switch for mesh functionality
#define MESH_CHANNEL 1                // Channel dedicated to mesh relay ops

// --- POOL SETTINGS ---
const int TARGET_ACTIVE_POOL = 1500;   // Active devices in RAM
const int TARGET_DORMANT_POOL = 3000;  // Previously active devices "waiting" to either be dropped or re-introduced into the crowd 
