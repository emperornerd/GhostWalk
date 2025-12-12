/*
 * PROJECT: Ghost Walk
 * HARDWARE: ESP32 (WiFi Shield) / ESP32-C5 (Dual Band)
 * VERSION: 9.4.2 - "Radio Time Analytics" (Patched)
 * PURPOSE: High-density crowd simulation with forensic hardening + best-effort mesh relay.
 * FEATURES: Interleaved Dual-Band Hopping, Sticky RSSI, HT/VHT Beacons.
 * UPDATE: Fixed sender duplication (Data frame filtering) & Self-detection loop.
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <esp_wifi_types.h> 
#include <esp_mac.h> 
#include <vector>
#include <deque>
#include <algorithm>
#include <TFT_eSPI.h> 
#include <SPI.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

// --- HARDWARE DETECTION ---
#if defined(CONFIG_IDF_TARGET_ESP32C5)
    #define HARDWARE_IS_C5 true
    #define MAX_SUPPORTED_BAND 2 // 0=2.4, 1=5
#else
    #define HARDWARE_IS_C5 false
    #define MAX_SUPPORTED_BAND 1
#endif

// --- CONFIGURATION ---
#define ENABLE_PASSIVE_SCAN true      
#define ENABLE_SSID_REPLICATION true  
#define ENABLE_LIFECYCLE_SIM true     
#define ENABLE_SEQUENCE_GAPS true     
#define ENABLE_BEACON_EMULATION true
#define ENABLE_INTERACTION_SIM true   

// --- MESH RELAY CONFIGURATION (DYNAMIC INTERVALS) ---
#define ENABLE_MESH_RELAY true // Master switch for mesh functionality
#define MESH_CHANNEL 1 
// MESH_ACTIVE_INTERVAL_MS: Frequency of checks *while* a mesh is detected (Fast Check)
const unsigned long MESH_ACTIVE_INTERVAL_MS = 600000; 
// MESH_STANDBY_INTERVAL_MS: Frequency of checks *while* no mesh is detected (Slow Check)
const unsigned long MESH_STANDBY_INTERVAL_MS = 20000;
// Listen duration: Very short to minimize disruption
const unsigned long MESH_CHECK_DURATION_MS = 100; 
// Chance to rebroadcast a cached mesh packet during a Ghost Walk TX slot
const int MESH_RELAY_CHANCE = 5; 

// NEW: Decay Timer Configuration
// Mesh data is considered fresh for 10 minutes after detection.
const unsigned long MESH_DECAY_TIMEOUT_MS = 600000; // 10 minutes (600,000ms)

// NEW: Queue and Sender Tracking
const int MAX_MESH_QUEUE_SIZE = 40; // Practical due to dynamic sizing
const unsigned long SENDER_TRACK_WINDOW_MS = 300000; // 5 Minutes

// --- POOL SETTINGS ---
const int TARGET_ACTIVE_POOL = 1500;
const int TARGET_DORMANT_POOL = 3000;
const int MAX_SSIDS_TO_LEARN = 200;
const int CYCLE_CAP_BUFFER = 5; 
const unsigned long LEARN_INTERVAL_MS = 60000 / 25; 
const unsigned long CYCLE_INTERVAL_MS = 10000; 

// --- TRAFFIC TIMING ---
const int MIN_PACKETS_PER_HOP = 20; 
const int MAX_PACKETS_PER_HOP = 45;
const int MIN_LIFECYCLE_MS = 3000; 
const int MAX_LIFECYCLE_MS = 6000;
const int MIN_CHANNEL_HOP_MS = 120; 
const int MAX_CHANNEL_HOP_MS = 300;

// --- POWER (Signal Strength) ---
const int8_t POWER_LEVELS[] = {72, 74, 76, 78, 80, 82};
const int MIN_TX_POWER = 72;
const int MAX_TX_POWER = 82;

// --- CHANNELS ---
const uint8_t CHANNELS_2G[] = {1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10}; 
const uint8_t CHANNELS_5G[] = {36, 149, 40, 153, 44, 157, 48, 161, 165}; 
const int NUM_CHANNELS_2G = 11;
const int NUM_CHANNELS_5G = 9;

// --- DEVICE GENERATIONS ---
enum DeviceGen {
    GEN_LEGACY,      // 802.11n (WiFi 4)
    GEN_COMMON,      // 802.11ac (WiFi 5)
    GEN_MODERN       // 802.11ax (WiFi 6)
};

enum OSPlatform {
    PLATFORM_IOS,
    PLATFORM_ANDROID,
    PLATFORM_OTHER
};

// --- EXPANDED VENDOR OUIS ---
const uint8_t OUI_APPLE[][3] = {
    {0xFC,0xFC,0x48}, {0xBC,0xD0,0x74}, {0xAC,0x1F,0x0F}, {0xF0,0xD4,0x15},
    {0xF0,0x98,0x9D}, {0x34,0x14,0x5F}, {0xDC,0xA9,0x04}, {0x28,0xCF,0xE9},
    {0xAC,0xBC,0x32}, {0xE4,0xCE,0x8F}, {0xBC,0x9F,0xEF}, {0x48,0x4B,0xAA},
    {0x88,0x66,0x5A}, {0x1C,0x91,0x48}, {0x60,0xFA,0xCD}
};
const int NUM_OUI_APPLE = 15;

const uint8_t OUI_SAMSUNG[][3] = {
    {0x24,0xFC,0xEE}, {0x8C,0x96,0xD4}, {0x5C,0xCB,0x99}, {0x34,0x21,0x09},
    {0x84,0x25,0xDB}, {0x00,0xE0,0x64}, {0x80,0xEA,0x96}, {0x38,0x01,0x95},
    {0xB0,0xC0,0x90}, {0xFC,0xC2,0xDE}
};
const int NUM_OUI_SAMSUNG = 10;

const uint8_t OUI_LEGACY_IOT[][3] = {
    {0x00,0x14,0x38}, {0x00,0x0D,0x93}, {0x00,0x1F,0x32}, {0x00,0x16,0x35},
    {0x00,0x04,0xBD}, {0x00,0x17,0xE0}, {0x00,0x1B,0x7A}
};
const int NUM_OUI_IOT = 7;

const uint8_t OUI_MODERN_GEN[][3] = {
    {0x3C,0x5C,0x48}, {0x8C,0xF5,0xA3}, {0x74,0xC6,0x3B}, {0xFC,0xA6,0x67},
    {0xE8,0x6A,0x64}, {0x60,0x55,0xF9}, {0xDC,0x8C,0x90}, {0x40,0x9F,0x38}
};
const int NUM_OUI_GENERIC = 8;

// --- GLOBALS ---
TFT_eSPI tft = TFT_eSPI();
QueueHandle_t ssidQueue;

// Mesh Queue and State
QueueHandle_t meshQueue;
unsigned long lastMeshCheckTime = 0;
unsigned long lastMeshPacketTime = 0; // Tracks when the last packet was seen
bool isMeshDetected = false; 
uint8_t local_mac_addr[6]; // Store local MAC to prevent self-detection

// NEW: Queue Structures
struct CachedMessage {
    std::vector<uint8_t> payload;
    unsigned long lastSeen;
};

struct MeshSender {
    uint8_t mac[6];
    unsigned long lastSeen;
};

std::deque<CachedMessage> meshCache;
std::vector<MeshSender> recentSenders;

struct SniffedSSID {
    char ssid[33];
};

struct MeshPacket {
    uint8_t payload[1024];
    int len;
};

int currentChannel = 1;
bool is5GHzBand = false;
int idx2G = 0; 
int idx5G = 0;
bool nextHopIs5G = true; 

unsigned long lastChannelHop = 0;
unsigned long lastLifecycleRun = 0;
unsigned long lastUiUpdateTime = 0;
unsigned long startTime = 0;
unsigned long lastSsidLearnTime = 0; 

unsigned long totalPacketCount = 0;
unsigned long learnedDataCount = 0;
unsigned long interactionCount = 0; 
unsigned long junkPacketCount = 0;
unsigned long sniffedPacketCount = 0;
unsigned long activeTimeTotal = 0; 
unsigned long meshRelayCount = 0; 

// New Time Tracking for Radio Usage Split
unsigned long meshRadioTime = 0;
unsigned long ghostRadioTime = 0;

String lastLearnedSSID = "None";

unsigned long packets2G = 0;
unsigned long packets5G = 0;

int nextChannelHopInterval = 250;
int nextLifecycleInterval = 3500;
bool lowMemoryMode = false;

// --- DATA POOLS ---
const char* SEED_SSIDS[] = {
  "xfinitywifi", "Starbucks WiFi", "attwifi", "Google Starbucks", 
  "iPhone", "AndroidAP", "Guest", "linksys", "netgear",
  "Free Public WiFi", "T-Mobile", "Home", "Office", 
  "Spectrum", "optimumwifi", "CoxWiFi", "Lowe's Wi-Fi", 
  "Target Guest Wi-Fi", "McDonalds Free WiFi", "BURGER KING FREE WIFI", 
  "Subway WiFi", "PaneraBread_WiFi", "Airport_Free_WiFi", 
  "Marriott_Guest", "Hilton_Honors", "Walmart_WiFi", 
  "DIRECTV_WIFI", "HP-Print-B2-LaserJet", "Roku-829", "Sonos_WiFi"
};
const int NUM_SEED_SSIDS = 30;

std::vector<String> activeSSIDs; 

struct VirtualDevice {
    uint8_t mac[6];
    uint8_t bssid_target[6];
    uint16_t sequenceNumber;
    int preferredSSIDIndex;
    DeviceGen generation;
    OSPlatform platform;
    bool hasConnected;
    int8_t txPower; // STICKY POWER
};

std::vector<VirtualDevice> activeSwarm;
std::vector<VirtualDevice> dormantSwarm;
uint8_t packetBuffer[1024];
uint8_t noiseBuffer[256];

// --- SANITIZED PAYLOADS ---
const uint8_t HT_CAPS_PAYLOAD[] = {0xEF, 0x01, 0x1B, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t VHT_CAPS_PAYLOAD[] = {0x91, 0x59, 0x82, 0x0F, 0xEA, 0xFF, 0x00, 0x00, 0xEA, 0xFF, 0x00, 0x00};
const uint8_t HE_CAPS_PAYLOAD[] = {0x23, 0x09, 0x01, 0x00, 0x02, 0x40, 0x00, 0x04, 0x70, 0x0C, 0x89, 0x7F, 0x03, 0x80, 0x04, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA};
const uint8_t APPLE_VEND_PAYLOAD[] = {0x00, 0x17, 0xF2, 0x0A, 0x00, 0x01, 0x04};
const uint8_t WFA_VEND_PAYLOAD[] = {0x00, 10, 0x18, 0x02, 0x00, 0x00, 0x1C, 0x00, 0x00};
const uint8_t RSN_PAYLOAD[] = {0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00};

// Rates
const uint8_t RATES_LEGACY[] = {0x82, 0x84, 0x8b, 0x96}; 
const uint8_t RATES_MODERN_2G[] = {0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24}; 
const uint8_t RATES_5G[] = {0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c};

// --- FUNCTION IMPLEMENTATIONS ---

int addTag(uint8_t* buf, int ptr, uint8_t id, const uint8_t* data, int len) {
    buf[ptr++] = id;
    buf[ptr++] = len;
    memcpy(&buf[ptr], data, len);
    return ptr + len;
}

// --- RESOURCE MANAGEMENT ---
void manageResources() {
    uint32_t freeHeap = ESP.getFreeHeap();
    
    // Aggressive Cleanup Threshold
    if (freeHeap < 25000) {
        lowMemoryMode = true;
        
        // 1. Drop Dormant Swarm first (Least valuable)
        if (!dormantSwarm.empty()) {
            // Drop 30% of dormant to free contiguous blocks
            int dropCount = dormantSwarm.size() * 0.30;
            if (dropCount > 0) {
                dormantSwarm.erase(dormantSwarm.begin(), dormantSwarm.begin() + dropCount);
            }
        }
        
        // 2. If still critically low, prune Active Swarm
        if (freeHeap < 15000 && !activeSwarm.empty()) {
            int dropCount = activeSwarm.size() * 0.15;
            if (dropCount > 0) {
                 activeSwarm.erase(activeSwarm.begin(), activeSwarm.begin() + dropCount);
            }
            // Also stop learning new SSIDs in critical mode
        }
    } else {
        lowMemoryMode = false;
    }
}

void manageMeshResources(unsigned long currentMillis) {
    // 1. Prune Timed-out Senders (5 Minute Window)
    auto senderIt = recentSenders.begin();
    while (senderIt != recentSenders.end()) {
        if (currentMillis - senderIt->lastSeen > SENDER_TRACK_WINDOW_MS) {
            senderIt = recentSenders.erase(senderIt);
        } else {
            ++senderIt;
        }
    }

    // 2. Prune Timed-out Messages (10 Minute Timeout)
    auto msgIt = meshCache.begin();
    while (msgIt != meshCache.end()) {
        if (currentMillis - msgIt->lastSeen > MESH_DECAY_TIMEOUT_MS) {
            msgIt = meshCache.erase(msgIt);
        } else {
            ++msgIt;
        }
    }
}

// --- PASSIVE SCANNER (THREAD SAFE) ---
void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!ENABLE_PASSIVE_SCAN) return;
    if (type != WIFI_PKT_MGMT) return;
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* frame = pkt->payload;

    sniffedPacketCount++; // Track Monitor Activity
    
    if (frame[0] != 0x40) return; // Only Probe Requests
    
    int pos = 24;
    if (frame[pos] == 0x00) {
        int len = frame[pos+1];
        if (len > 1 && len < 32) {
            SniffedSSID s;
            memcpy(s.ssid, &frame[pos+2], len);
            s.ssid[len] = '\0';
            xQueueSendFromISR(ssidQueue, &s, NULL);
        }
    }
}

// --- MESH SNIFFER (UPDATED: FIXED DOUBLE-COUNTING) ---
void IRAM_ATTR meshSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!ENABLE_MESH_RELAY) return;

    // We ONLY care about Management frames (specifically Action frames) for ESP-NOW.
    // Data frames (WIFI_PKT_DATA) are ignored to prevent counting standard HTTP/Data traffic.
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    // Strict Filter for ESP-NOW Action Frames
    // Frame Control (Byte 0) must be 0xD0 (Action Frame)
    if (frame[0] != 0xD0) return;

    // Minimum expected size for ESP-NOW (Header + Tag + OUI + Content)
    if (len < 40 || len > 1024) return;

    // OPTIONAL: Verify Espressif OUI to be absolutely sure it is mesh traffic
    // Action Frame Header: FC(2) + Dur(2) + Addr1(6) + Addr2(6) + Addr3(6) + Seq(2) = 24 Bytes
    // Category Code is at offset 24 (Should be 127 for Vendor Specific)
    // OUI is at offsets 25, 26, 27 (Should be 0x18, 0xFE, 0x34)
    if (frame[24] != 127) return; 
    if (frame[25] != 0x18 || frame[26] != 0xFE || frame[27] != 0x34) return;

    MeshPacket mp;
    if (len <= 1024) {
        memcpy(mp.payload, frame, len);
        mp.len = len;
        xQueueSendFromISR(meshQueue, &mp, NULL); 
    }
}

// --- STRICT IDENTITY GENERATOR ---
void generateWeightedIdentity(VirtualDevice& vd) {
    int roll = random(100); 
    const uint8_t* selectedOUI;
    DeviceGen gen;
    OSPlatform plat;

    // UPDATED DISTRIBUTION:
    // Apple: 40% (0-39)
    // Samsung: 35% (40-74)
    // Legacy IoT: 7% (75-81)
    // Modern Generic: 18% (82-99)

    if (roll < 40) { // Apple
        selectedOUI = OUI_APPLE[random(NUM_OUI_APPLE)];
        gen = (random(100) < 80) ? GEN_COMMON : GEN_MODERN; 
        plat = PLATFORM_IOS;
    } 
    else if (roll < 75) { // Samsung
        selectedOUI = OUI_SAMSUNG[random(NUM_OUI_SAMSUNG)];
        gen = (random(100) < 70) ? GEN_COMMON : GEN_MODERN; 
        plat = PLATFORM_ANDROID;
    }
    else if (roll < 82) { // IoT / Legacy (Increased)
        selectedOUI = OUI_LEGACY_IOT[random(NUM_OUI_IOT)];
        gen = GEN_LEGACY; 
        plat = PLATFORM_OTHER;
    }
    else { // Modern Generic (Intel/Amazon/Google) - Significant Increase
        selectedOUI = OUI_MODERN_GEN[random(NUM_OUI_GENERIC)];
        gen = GEN_MODERN; 
        plat = PLATFORM_ANDROID;
    }

    vd.generation = gen;
    vd.platform = plat;
    vd.hasConnected = false;
    
    int pIdx = random(sizeof(POWER_LEVELS)/sizeof(POWER_LEVELS[0]));
    vd.txPower = POWER_LEVELS[pIdx];

    // Use Locally Administered (Private) MACs for modern/common devices
    bool usePrivate = (gen == GEN_MODERN && random(100) < 85) ||
                      (gen == GEN_COMMON && random(100) < 50);
    
    if (usePrivate) {
        vd.mac[0] = (random(256) & 0xFE) | 0x02; 
        vd.mac[1] = random(256); vd.mac[2] = random(256);
    } else {
        vd.mac[0] = selectedOUI[0]; vd.mac[1] = selectedOUI[1]; vd.mac[2] = selectedOUI[2];
    }
    vd.mac[3] = random(256); vd.mac[4] = random(256); vd.mac[5] = random(256);
    
    // Target AP MAC (randomized but sticky)
    vd.bssid_target[0] = 0x00; vd.bssid_target[1] = 0x11; vd.bssid_target[2] = 0x32;
    vd.bssid_target[3] = random(256); vd.bssid_target[4] = random(256); vd.bssid_target[5] = random(256);
    
    vd.sequenceNumber = random(4096);
    
    int probeChance = (gen == GEN_LEGACY) ? 90 : 60;
    vd.preferredSSIDIndex = (random(100) < probeChance && !activeSSIDs.empty()) ?
                            random(activeSSIDs.size()) : -1;
}

void initSwarm() {
    for (int i=0; i<NUM_SEED_SSIDS; i++) activeSSIDs.push_back(SEED_SSIDS[i]);
    // Reserve memory to prevent reallocations
    activeSwarm.reserve(TARGET_ACTIVE_POOL);
    dormantSwarm.reserve(TARGET_DORMANT_POOL);
    
    // Initial Population
    for(int i=0; i<TARGET_ACTIVE_POOL; i++) {
        VirtualDevice vd;
        generateWeightedIdentity(vd);
        activeSwarm.push_back(vd);
        // Safety check during init
        if (ESP.getFreeHeap() < 20000) break;
    }
}

void processLifecycle() {
    // 1. Remove an old agent
    if (!activeSwarm.empty()) {
        int idx = random(activeSwarm.size());
        VirtualDevice leaving = activeSwarm[idx];
        
        // Only move to dormant if we have space and memory
        if (dormantSwarm.size() < TARGET_DORMANT_POOL && !lowMemoryMode) {
            dormantSwarm.push_back(leaving);
        }
        activeSwarm.erase(activeSwarm.begin() + idx);
    }
    
    // 2. Add a new agent (Swap from dormant or create new)
    if (lowMemoryMode && activeSwarm.size() > 800) return;

    VirtualDevice arriving;
    if (ENABLE_LIFECYCLE_SIM && !dormantSwarm.empty() && random(100) < 50) {
        int dIdx = random(dormantSwarm.size());
        arriving = dormantSwarm[dIdx];
        dormantSwarm.erase(dormantSwarm.begin() + dIdx);
        
        arriving.sequenceNumber = (arriving.sequenceNumber + random(50, 500)) % 4096;
        if (random(100) < 30) arriving.txPower += (random(3) - 1) * 2; 
        arriving.hasConnected = false;
    } else {
        generateWeightedIdentity(arriving);
    }
    
    // Clamp Power
    if (arriving.txPower < MIN_TX_POWER) arriving.txPower = MIN_TX_POWER;
    if (arriving.txPower > MAX_TX_POWER) arriving.txPower = MAX_TX_POWER;

    activeSwarm.push_back(arriving);
}

// --- NOISE GENERATOR ---
void fillSilenceWithNoise(unsigned long durationMs) {
    unsigned long start = millis();
    // Noise power floor
    int noisePower = 68 + random(0, 6); 
    esp_wifi_set_max_tx_power(noisePower); 
    
    while (millis() - start < durationMs) {
        uint8_t noiseMac[6];
        
        // Uses Locally Administered Random MACs (Private) to simulate background randomization
        noiseMac[0] = (random(256) & 0xFE) | 0x02; 
        noiseMac[1] = random(256); noiseMac[2] = random(256);
        noiseMac[3] = random(256); noiseMac[4] = random(256); noiseMac[5] = random(256);

        noiseBuffer[0] = 0x40; // Probe Request
        noiseBuffer[1] = 0x00; noiseBuffer[2] = 0x00; noiseBuffer[3] = 0x00;
        memset(&noiseBuffer[4], 0xFF, 6);
        memcpy(&noiseBuffer[10], noiseMac, 6); 
        memset(&noiseBuffer[16], 0xFF, 6);
        uint16_t seq = random(4096);
        noiseBuffer[22] = seq & 0xFF; noiseBuffer[23] = (seq >> 8) & 0xF0;
        
        int ptr = 24;
        // Mixed wildcard and "Hidden Network" style checks
        if (random(100) < 40) {
            int noiseLen = random(5, 12);
            noiseBuffer[ptr++] = 0x00; 
            noiseBuffer[ptr++] = noiseLen;
            for(int x=0; x<noiseLen; x++) noiseBuffer[ptr++] = random(97, 122); 
        } else {
            noiseBuffer[ptr++] = 0x00; noiseBuffer[ptr++] = 0x00;
        }

        if (is5GHzBand) {
             ptr = addTag(noiseBuffer, ptr, 0x01, RATES_5G, sizeof(RATES_5G));
        } else {
             uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96};
             ptr = addTag(noiseBuffer, ptr, 0x01, rates, 4);
        }

        esp_wifi_80211_tx(WIFI_IF_STA, noiseBuffer, ptr, false);
        totalPacketCount++;
        junkPacketCount++;
        yield();
    }
}

// --- PACKET BUILDERS ---

int buildAuthPacket(uint8_t* buf, VirtualDevice& vd) {
    buf[0] = 0xB0; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x01; 
    memcpy(&buf[4], vd.bssid_target, 6); 
    memcpy(&buf[10], vd.mac, 6);         
    memcpy(&buf[16], vd.bssid_target, 6);
    uint16_t seq = vd.sequenceNumber;
    buf[22] = seq & 0xFF; buf[23] = (seq >> 8) & 0xF0;
    int ptr = 24;
    buf[ptr++] = 0x00; buf[ptr++] = 0x00; 
    buf[ptr++] = 0x01; buf[ptr++] = 0x00; 
    buf[ptr++] = 0x00; buf[ptr++] = 0x00; 
    return ptr;
}

int buildAssocRequestPacket(uint8_t* buf, VirtualDevice& vd, String ssid) {
    buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00; 
    memcpy(&buf[4], vd.bssid_target, 6); 
    memcpy(&buf[10], vd.mac, 6);         
    memcpy(&buf[16], vd.bssid_target, 6);
    uint16_t seq = vd.sequenceNumber;
    buf[22] = seq & 0xFF; buf[23] = (seq >> 8) & 0xF0;
    int ptr = 24;
    buf[ptr++] = 0x31; buf[ptr++] = 0x04; 
    buf[ptr++] = 0x0A; buf[ptr++] = 0x00; 
    buf[ptr++] = 0x00; buf[ptr++] = ssid.length();
    memcpy(&buf[ptr], ssid.c_str(), ssid.length());
    ptr += ssid.length();
    
    if (is5GHzBand) {
        ptr = addTag(buf, ptr, 0x01, RATES_5G, sizeof(RATES_5G));
    } else {
        if (vd.generation == GEN_LEGACY) ptr = addTag(buf, ptr, 0x01, RATES_LEGACY, sizeof(RATES_LEGACY));
        else ptr = addTag(buf, ptr, 0x01, RATES_MODERN_2G, sizeof(RATES_MODERN_2G));
    }
    
    ptr = addTag(buf, ptr, 48, RSN_PAYLOAD, sizeof(RSN_PAYLOAD));
    ptr = addTag(buf, ptr, 45, HT_CAPS_PAYLOAD, sizeof(HT_CAPS_PAYLOAD)); 
    if (vd.generation != GEN_LEGACY) ptr = addTag(buf, ptr, 191, VHT_CAPS_PAYLOAD, sizeof(VHT_CAPS_PAYLOAD));
    
    if (vd.generation == GEN_MODERN) {
         buf[ptr++] = 255; 
         buf[ptr++] = sizeof(HE_CAPS_PAYLOAD) + 1;
         buf[ptr++] = 35; 
         memcpy(&buf[ptr], HE_CAPS_PAYLOAD, sizeof(HE_CAPS_PAYLOAD));
         ptr += sizeof(HE_CAPS_PAYLOAD);
    }
    return ptr;
}

int buildEncryptedDataPacket(uint8_t* buf, VirtualDevice& vd) {
    buf[0] = 0x88; buf[1] = 0x41; buf[2] = 0x00; buf[3] = 0x00; 
    memcpy(&buf[4], vd.bssid_target, 6); 
    memcpy(&buf[10], vd.mac, 6);         
    memcpy(&buf[16], vd.bssid_target, 6);
    uint16_t seq = vd.sequenceNumber;
    buf[22] = seq & 0xFF; buf[23] = (seq >> 8) & 0xF0;
    int ptr = 24;
    buf[ptr++] = random(0, 8); buf[ptr++] = 0x00; 
    int payloadLen = random(64, 512); 
    for(int i=0; i<payloadLen; i++) buf[ptr++] = random(0, 256);
    return ptr;
}

int buildProbePacket(uint8_t* buf, VirtualDevice& vd, int channel) {
    buf[0] = 0x40; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00;
    memset(&buf[4], 0xFF, 6); 
    memcpy(&buf[10], vd.mac, 6); 
    memset(&buf[16], 0xFF, 6);
    uint16_t seq = vd.sequenceNumber;
    buf[22] = seq & 0xFF; buf[23] = (seq >> 8) & 0xF0;
    int ptr = 24;

    bool useWildcard = false;
    if (vd.generation == GEN_LEGACY || vd.platform == PLATFORM_OTHER) {
        if (random(100) < 40) useWildcard = true;
    }
    
    if (useWildcard) {
        buf[ptr++] = 0x00; buf[ptr++] = 0x00; 
    } else {
        String ssid;
        if (vd.preferredSSIDIndex != -1 && vd.preferredSSIDIndex < activeSSIDs.size() && !activeSSIDs.empty()) {
            ssid = activeSSIDs[vd.preferredSSIDIndex];
        } else if (!activeSSIDs.empty()) {
             ssid = activeSSIDs[random(activeSSIDs.size())];
        } else {
             char temp[8];
             for(int i=0;i<7;i++) temp[i] = (char)random(97,122);
             temp[7]=0;
             ssid = String(temp);
        }
        buf[ptr++] = 0x00; buf[ptr++] = ssid.length();
        memcpy(&buf[ptr], ssid.c_str(), ssid.length()); ptr += ssid.length();
    }

    if (is5GHzBand) {
        ptr = addTag(buf, ptr, 0x01, RATES_5G, sizeof(RATES_5G));
    } else {
        if (vd.generation == GEN_LEGACY) ptr = addTag(buf, ptr, 0x01, RATES_LEGACY, sizeof(RATES_LEGACY));
        else ptr = addTag(buf, ptr, 0x01, RATES_MODERN_2G, sizeof(RATES_MODERN_2G));
    }

    buf[ptr++] = 0x03; buf[ptr++] = 0x01; buf[ptr++] = (uint8_t)channel;

    bool isApple = (vd.platform == PLATFORM_IOS);
    if (isApple) {
        uint8_t extCap[] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40};
        ptr = addTag(buf, ptr, 127, extCap, 8);
    }

    ptr = addTag(buf, ptr, 45, HT_CAPS_PAYLOAD, sizeof(HT_CAPS_PAYLOAD));

    if (vd.generation != GEN_LEGACY) {
        ptr = addTag(buf, ptr, 191, VHT_CAPS_PAYLOAD, sizeof(VHT_CAPS_PAYLOAD));
    }

    if (!isApple && vd.generation != GEN_LEGACY) {
        uint8_t extCapAnd[] = {0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40};
        ptr = addTag(buf, ptr, 127, extCapAnd, 8);
    }

    if (vd.generation == GEN_MODERN) {
         buf[ptr++] = 255; 
         buf[ptr++] = sizeof(HE_CAPS_PAYLOAD) + 1;
         buf[ptr++] = 35; 
         memcpy(&buf[ptr], HE_CAPS_PAYLOAD, sizeof(HE_CAPS_PAYLOAD));
         ptr += sizeof(HE_CAPS_PAYLOAD);
    }

    ptr = addTag(buf, ptr, 221, WFA_VEND_PAYLOAD, sizeof(WFA_VEND_PAYLOAD));
    if (isApple) ptr = addTag(buf, ptr, 221, APPLE_VEND_PAYLOAD, sizeof(APPLE_VEND_PAYLOAD));
    
    return ptr;
}

int buildBeaconPacket(uint8_t* buf, uint8_t* mac, const String& ssid, int channel, uint16_t seqNum) {
    buf[0] = 0x80; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00;
    memset(&buf[4], 0xFF, 6);
    memcpy(&buf[10], mac, 6); memcpy(&buf[16], mac, 6);
    buf[22] = seqNum & 0xFF; buf[23] = (seqNum >> 8) & 0xF0;
    int ptr = 24;
    memset(&buf[ptr], 0x00, 8); ptr += 8; 
    buf[ptr++] = 0x64; buf[ptr++] = 0x00; 
    buf[ptr++] = 0x31; buf[ptr++] = 0x04; 
    buf[ptr++] = 0x00; buf[ptr++] = ssid.length();
    memcpy(&buf[ptr], ssid.c_str(), ssid.length()); ptr += ssid.length();
    
    if (is5GHzBand) {
        ptr = addTag(buf, ptr, 0x01, RATES_5G, sizeof(RATES_5G));
    } else {
        ptr = addTag(buf, ptr, 0x01, RATES_LEGACY, sizeof(RATES_LEGACY));
    }
    
    buf[ptr++] = 0x03; buf[ptr++] = 0x01; buf[ptr++] = (uint8_t)channel;
    
    // HT/VHT Operation Tags
    uint8_t htOp[] = {(uint8_t)channel, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
    ptr = addTag(buf, ptr, 61, htOp, 22);

    // VHT Operation (Tag 192) remains 5GHz specific (802.11ac)
    if (is5GHzBand) {
         uint8_t vhtOp[] = {0x00, 0x00, 0x00, 0x00, 0x00};
         ptr = addTag(buf, ptr, 192, vhtOp, 5);
    }
    
    return ptr;
}


// --- DISPLAY (MODIFIED for dynamic mesh stats) ---
void updateDisplayStats(unsigned long currentMillis) {
    tft.fillRect(5, 40, 230, 200, TFT_BLACK); 
    tft.setTextSize(1);
    
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.setCursor(5, 50); tft.printf("--- TRAFFIC METRICS ---"); 
    
    if (lowMemoryMode) tft.setTextColor(TFT_RED, TFT_BLACK);
    else tft.setTextColor(TFT_GREEN, TFT_BLACK);
    
    tft.setCursor(5, 65); 
    tft.printf("Free RAM: %d KB %s", ESP.getFreeHeap()/1024, lowMemoryMode ? "[LOW]" : ""); 
    
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.setCursor(5, 77); 
    tft.printf("Active: %d | Dormant: %d", activeSwarm.size(), dormantSwarm.size());
    
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setCursor(5, 89); 
    tft.printf("Total Packets: %lu", totalPacketCount);
    tft.setCursor(5, 101); 
    tft.printf("Junk: %lu", junkPacketCount); 

    unsigned long total = packets2G + packets5G;
    int p2g = (total > 0) ? (packets2G * 100 / total) : 0;
    int p5g = (total > 0) ? (packets5G * 100 / total) : 0;
    
    // UPDATED BAND LINE: Already uses [Value%] format
    tft.setTextColor(TFT_CYAN, TFT_BLACK);
    tft.setCursor(5, 115); 
    String hwType = HARDWARE_IS_C5 ? "Dual" : "Single";
    tft.printf("Band: 2.4G[%d%%] 5G[%d%%] (%s)", p2g, p5g, hwType.c_str());

    tft.setTextColor(TFT_ORANGE, TFT_BLACK);
    tft.setCursor(5, 127); 
    tft.printf("Found SSIDs: %lu / %d", learnedDataCount, MAX_SSIDS_TO_LEARN);
    
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.setCursor(5, 139); 
    String truncSSID = lastLearnedSSID;
    if (truncSSID.length() > 22) truncSSID = truncSSID.substring(0, 22) + "...";
    tft.printf("Last: %s", truncSSID.c_str());
    
    unsigned long upSec = (currentMillis - startTime) / 1000;
    int hr = upSec / 3600;
    int mn = (upSec % 3600) / 60;
    int sc = upSec % 60;
    
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.setCursor(5, 155); 
    tft.printf("Uptime: %02d:%02d:%02d", hr, mn, sc);

    unsigned long runTime = currentMillis - startTime;
    float idle = 0;
    if(runTime > 0) idle = 100.0 * (1.0 - ((float)activeTimeTotal / runTime));
    
    unsigned long totalAct = totalPacketCount + sniffedPacketCount;
    int monPct = 0;
    if(totalAct > 0) monPct = (sniffedPacketCount * 100) / totalAct;
    
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setCursor(5, 165); 
    // MODIFIED: Changed "M/B: %d/%d%%" to "M[%d%%] B[%d%%]" for consistency
    tft.printf("Idle: %0.1f%% | M[%d%%] B[%d%%]", idle, monPct, 100-monPct);

    // NEW LINE: Cache Size & Radio Time Split (Already uses [Value%] format)
    tft.setCursor(5, 175); 
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    unsigned long totalRadio = meshRadioTime + ghostRadioTime;
    int meshPct = (totalRadio > 0) ? (meshRadioTime * 100 / totalRadio) : 0;
    int ghostPct = (totalRadio > 0) ? 100 - meshPct : 0;
    tft.printf("Cache: %d | Radio: M[%d%%] G[%d%%]", meshCache.size(), meshPct, ghostPct);
    
    // NEW: Mesh Status & Dedication (ENHANCED DYNAMIC DISPLAY)
    tft.setCursor(5, 187); 
    if (!ENABLE_MESH_RELAY) {
        tft.setTextColor(TFT_RED, TFT_BLACK);
        tft.printf("MESH RELAY: DISABLED BY FLAG");
        tft.setCursor(5, 199); 
        tft.printf("Dedication: 0%%");
    } else if(isMeshDetected) {
        tft.setTextColor(TFT_GREEN, TFT_BLACK);
        // Show remaining time based on decay timeout (10 minutes)
        unsigned long timeRemaining = (MESH_DECAY_TIMEOUT_MS > (currentMillis - lastMeshPacketTime)) 
                                    ? (MESH_DECAY_TIMEOUT_MS - (currentMillis - lastMeshPacketTime)) : 0;
        
        tft.printf("MESH RELAY: ACTIVE (T-%lums)", timeRemaining);
        tft.setCursor(5, 199); 
        // Show Queue Status
        tft.printf("Q: %d/%d | Senders(5m): %d", meshCache.size(), MAX_MESH_QUEUE_SIZE, recentSenders.size()); 
    } else {
        tft.setTextColor(TFT_ORANGE, TFT_BLACK);
        // When inactive, show the T-minus countdown for the next 10-minute check
        unsigned long timeRemaining = (MESH_STANDBY_INTERVAL_MS > (currentMillis - lastMeshCheckTime)) 
                                    ? (MESH_STANDBY_INTERVAL_MS - (currentMillis - lastMeshCheckTime)) : 0;
        
        tft.printf("MESH RELAY: STANDBY | Check T-%lus", timeRemaining / 1000);
        tft.setCursor(5, 199); 
        tft.printf("checking..."); 
    }

    // ADDED: Explicit Rebroadcast Counter
    tft.setCursor(5, 211);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.printf("Total Relayed: %lu", meshRelayCount);
}

void setupDisplay() {
  tft.init();
  tft.setRotation(1); tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_ORANGE, TFT_BLACK); tft.setTextSize(2);
  tft.setCursor(5, 5);
  tft.println("GHOST WALK v9.4.2"); // Updated version number
  tft.drawRect(0, 0, tft.width(), tft.height(), TFT_DARKGREY);
  tft.setTextSize(1);
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  
  tft.setCursor(5, 30); 
  if (HARDWARE_IS_C5) tft.printf("HW: ESP32-C5 (Dual)");
  else tft.printf("HW: Standard (2.4G)");
  
  updateDisplayStats(millis()); 
}

// --- MESH CHECK INTERRUPT ---
void checkAndListenForMesh() {
    if (!ENABLE_MESH_RELAY) return; // Exit if disabled

    // 1. Temporarily change RX callback to the mesh sniffer
    esp_wifi_set_promiscuous_rx_cb(meshSnifferCallback);
    
    // 2. Switch to Mesh Channel (Channel 1)
    esp_wifi_set_channel(MESH_CHANNEL, WIFI_SECOND_CHAN_NONE);

    unsigned long start = millis();
    // 3. Listen for a brief duration (100ms)
    while (millis() - start < MESH_CHECK_DURATION_MS) {
        MeshPacket mp;
        // Non-blocking check for a received packet
        if (xQueueReceive(meshQueue, &mp, 0) == pdTRUE) {
            
            // --- SENDER TRACKING (Last 5 Minutes) ---
            // 802.11 Header: Source Address (SA) is usually Address 2 (offset 10)
            if (mp.len >= 16) {
                uint8_t senderMac[6];
                memcpy(senderMac, &mp.payload[10], 6);

                // --- FIX: SELF-DETECTION CHECK ---
                // Do not count ourselves as a sender (fixes "and itself" count)
                if (memcmp(senderMac, local_mac_addr, 6) == 0) continue; 
                
                bool senderKnown = false;
                for (auto& s : recentSenders) {
                    if (memcmp(s.mac, senderMac, 6) == 0) {
                        s.lastSeen = millis();
                        senderKnown = true;
                        break;
                    }
                }
                if (!senderKnown) {
                    MeshSender newSender;
                    memcpy(newSender.mac, senderMac, 6);
                    newSender.lastSeen = millis();
                    recentSenders.push_back(newSender);
                }
            }

            // --- QUEUE MANAGEMENT (40 Message FIFO with Refresh) ---
            bool msgKnown = false;
            for (auto& cached : meshCache) {
                if (cached.payload.size() == mp.len && 
                    memcmp(cached.payload.data(), mp.payload, mp.len) == 0) {
                    // Duplicate: Reset Timeout
                    cached.lastSeen = millis();
                    msgKnown = true;
                    break;
                }
            }

            if (!msgKnown) {
                // Remove oldest if full
                if (meshCache.size() >= MAX_MESH_QUEUE_SIZE) {
                    meshCache.pop_front();
                }
                
                CachedMessage newMsg;
                newMsg.payload.assign(mp.payload, mp.payload + mp.len);
                newMsg.lastSeen = millis();
                meshCache.push_back(newMsg);
            }

            isMeshDetected = true; // Mesh is confirmed active
            lastMeshPacketTime = millis(); // Record successful reception time
        }
        yield();
    }
    
    // NEW: Time Tracking
    unsigned long duration = millis() - start;
    meshRadioTime += duration;
    
    // 4. Restore the Ghost Walk sniffer callback (for Probe Request learning)
    esp_wifi_set_promiscuous_rx_cb(snifferCallback);
}


void setup() {
  Serial.begin(115200);
  
  ssidQueue = xQueueCreate(20, sizeof(SniffedSSID));
  if (ENABLE_MESH_RELAY) {
      meshQueue = xQueueCreate(5, sizeof(MeshPacket)); // Initialize Mesh Queue only if enabled
  }

  uint8_t mac_base[6];
  esp_read_mac(mac_base, ESP_MAC_WIFI_STA);
  // Store local MAC specifically for the filter
  memcpy(local_mac_addr, mac_base, 6);

  randomSeed(analogRead(0) * micros() + mac_base[5]);
  startTime = millis();
  
  setupDisplay();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  if (esp_wifi_init(&cfg) != ESP_OK) while(1);
  
  if (ENABLE_PASSIVE_SCAN) {
    esp_wifi_set_promiscuous(true);
    // Start with the default sniffer for Probe Request learning
    esp_wifi_set_promiscuous_rx_cb(snifferCallback); 
  }
  
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  esp_wifi_set_max_tx_power(POWER_LEVELS[4]); 

  initSwarm();
}

void loop() {
  unsigned long currentMillis = millis(); 

  SniffedSSID s;
  while (xQueueReceive(ssidQueue, &s, 0) == pdTRUE) {
      String newSSID = String(s.ssid);
      
      if (ENABLE_SSID_REPLICATION && !lowMemoryMode) {
          bool known = false;
          for (auto& existing : activeSSIDs) {
              if (existing.equals(newSSID)) {
                  known = true;
                  break;
              }
          }
          
          if (!known) {
              unsigned long requiredInterval = (activeSSIDs.size() >= MAX_SSIDS_TO_LEARN) ? 
                                               CYCLE_INTERVAL_MS : LEARN_INTERVAL_MS;

              if (activeSSIDs.size() < MAX_SSIDS_TO_LEARN + CYCLE_CAP_BUFFER) {
                  activeSSIDs.push_back(newSSID);
                  learnedDataCount++;
                  lastLearnedSSID = newSSID;
                  lastSsidLearnTime = currentMillis; 
              } 
              else if (currentMillis - lastSsidLearnTime >= requiredInterval) {
                  if (activeSSIDs.size() > NUM_SEED_SSIDS) {
                      int cycleIdx = random(NUM_SEED_SSIDS, activeSSIDs.size()); 
                      activeSSIDs[cycleIdx] = newSSID; 
                      lastLearnedSSID = newSSID;
                      lastSsidLearnTime = currentMillis; 
                  }
              }
          }
      }
  }

  manageResources();
  manageMeshResources(currentMillis); // Prune old mesh messages and senders

  if (currentMillis - lastLifecycleRun > nextLifecycleInterval) {
      lastLifecycleRun = currentMillis;
      // Using 66/100 (2/3) multiplier to meet the faster processing requirement 
      nextLifecycleInterval = random(MIN_LIFECYCLE_MS * 66 / 100, MAX_LIFECYCLE_MS * 66 / 100); 
      int rotateCount = random(3, 8);
      for(int i=0; i<rotateCount; i++) processLifecycle();
  }

  // NEW: MESH DECAY TIMEOUT LOGIC
  // 1. Check if the active mode has timed out (10 minutes)
  if (ENABLE_MESH_RELAY && isMeshDetected && 
      currentMillis - lastMeshPacketTime > MESH_DECAY_TIMEOUT_MS) {
      
      isMeshDetected = false;
      meshCache.clear(); // Clear the cached packets on decay
  }
  
  // --- MESH CHECK INTERRUPT (DYNAMIC INTERVAL) ---
  if (ENABLE_MESH_RELAY) {
      unsigned long requiredInterval;

      // 2. Determine the interval based on state
      if (isMeshDetected) {
          // Mesh is active, use fast 300ms check
          requiredInterval = MESH_ACTIVE_INTERVAL_MS;
      } else {
          // Mesh is not active/decayed, use slow 10-minute check
          requiredInterval = MESH_STANDBY_INTERVAL_MS; 
      }

      // 3. Check if it's time to run the check
      if (currentMillis - lastMeshCheckTime > requiredInterval) {
          unsigned long meshCheckStart = millis();
          checkAndListenForMesh();
          lastMeshCheckTime = currentMillis;
          activeTimeTotal += (millis() - meshCheckStart); 
      }
  }
  // --- END MESH CHECK INTERRUPT ---


  if (currentMillis - lastChannelHop > nextChannelHopInterval) {
    unsigned long hopStart = millis(); // START TIMING ACTIVE BLOCK
    lastChannelHop = currentMillis;
    nextChannelHopInterval = random(MIN_CHANNEL_HOP_MS, MAX_CHANNEL_HOP_MS);
    
    // --- HOPPING LOGIC ---
    if (HARDWARE_IS_C5) {
        if (nextHopIs5G) {
            is5GHzBand = true;
            currentChannel = CHANNELS_5G[idx5G];
            idx5G++;
            if (idx5G >= NUM_CHANNELS_5G) idx5G = 0;
            nextHopIs5G = false; 
        } else {
            is5GHzBand = false;
            currentChannel = CHANNELS_2G[idx2G];
            idx2G++;
            if (idx2G >= NUM_CHANNELS_2G) idx2G = 0;
            nextHopIs5G = true; 
        }
    } else {
        is5GHzBand = false;
        currentChannel = CHANNELS_2G[idx2G];
        idx2G++;
        if (idx2G >= NUM_CHANNELS_2G) idx2G = 0;
    }

    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    int packetsThisHop = random(MIN_PACKETS_PER_HOP, MAX_PACKETS_PER_HOP);

    for (int i = 0; i < packetsThisHop; i++) {
        // --- MESH RELAY (MULTI-QUEUE) ---
        if (ENABLE_MESH_RELAY && !meshCache.empty() && 
            !is5GHzBand && currentChannel == MESH_CHANNEL && 
            random(100) < MESH_RELAY_CHANCE) {
            
            // Broadcast a cached mesh packet (randomly selected for diversity)
            int msgIdx = random(meshCache.size());
            const auto& msg = meshCache[msgIdx];

            esp_wifi_set_max_tx_power(MAX_TX_POWER); 
            esp_wifi_80211_tx(WIFI_IF_STA, msg.payload.data(), msg.payload.size(), false);
            meshRelayCount++;
            totalPacketCount++;
        }
        // --- END MESH RELAY ---
        
        // --- GHOST WALK PRIMARY SIMULATION ---
        if (!activeSwarm.empty()) {
            int swarmIdx = random(activeSwarm.size());
            VirtualDevice& vd = activeSwarm[swarmIdx];
            
            esp_wifi_set_max_tx_power(vd.txPower);

            if (is5GHzBand && vd.generation == GEN_LEGACY) continue;

            int pktLen = 0;

            if (ENABLE_INTERACTION_SIM && random(100) < 2 && vd.preferredSSIDIndex != -1 && vd.preferredSSIDIndex < activeSSIDs.size()) {
                 String targetSSID = activeSSIDs[vd.preferredSSIDIndex];
                 vd.hasConnected = true;
                 
                 pktLen = buildAuthPacket(packetBuffer, vd);
                 esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
                 vd.sequenceNumber = (vd.sequenceNumber + 1) % 4096;
                 
                 fillSilenceWithNoise(random(10 * 75 / 100, 40 * 50 / 100)); 

                 pktLen = buildAssocRequestPacket(packetBuffer, vd, targetSSID);
                 esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
                 vd.sequenceNumber = (vd.sequenceNumber + 1) % 4096;
                 
                 fillSilenceWithNoise(random(30 * 75 / 100, 100 * 50 / 100));

                 int burstCount = random(3, 12);
                 for(int b=0; b<burstCount; b++) {
                     pktLen = buildEncryptedDataPacket(packetBuffer, vd);
                     esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
                     vd.sequenceNumber = (vd.sequenceNumber + 1) % 4096;
                     totalPacketCount++;
                     if (is5GHzBand) packets5G++; else packets2G++;
                     fillSilenceWithNoise(random(5 * 75 / 100, 20 * 50 / 100));
                 }
                 interactionCount++;
            }
            else {
                pktLen = buildProbePacket(packetBuffer, vd, currentChannel);
                esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
                if (pktLen > 0) {
                    totalPacketCount++;
                    if (is5GHzBand) packets5G++; else packets2G++;
                    
                    int step = (ENABLE_SEQUENCE_GAPS && random(100) < 20) ? random(2, 8) : 1;
                    vd.sequenceNumber = (vd.sequenceNumber + step) % 4096;
                }
            }
        }
        
        // Router traffic rate is now dynamic (2% by default, 5% when soft cap (200) is reached)
        int beaconChance = 2; // Default 2%
        if (activeSSIDs.size() >= MAX_SSIDS_TO_LEARN) {
             beaconChance = 5; // User requested 5% for high-density simulation
        }

        if (ENABLE_BEACON_EMULATION && random(100) < beaconChance && !activeSSIDs.empty()) {
            int ssidIdx = random(activeSSIDs.size());
            String beaconSSID = activeSSIDs[ssidIdx];
            uint8_t mac[6]; 
            mac[0] = 0x02; mac[1] = 0x11; mac[2] = 0x22; 
            mac[3] = random(255); mac[4] = random(255); mac[5] = random(255);
            
            esp_wifi_set_max_tx_power(MAX_TX_POWER); 
            int pktLen = buildBeaconPacket(packetBuffer, mac, beaconSSID, currentChannel, random(4096));
            esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
            totalPacketCount++;
            if (is5GHzBand) packets5G++; else packets2G++;
        }

        fillSilenceWithNoise(random(2 * 75 / 100, 10 * 50 / 100));
    }
    
    // NEW: Time Tracking
    unsigned long hopDuration = millis() - hopStart;
    ghostRadioTime += hopDuration;
    activeTimeTotal += hopDuration; // END TIMING ACTIVE BLOCK
  }
  
  if (currentMillis - lastUiUpdateTime > 2000) {
      lastUiUpdateTime = currentMillis;
      updateDisplayStats(currentMillis); 
  }
}
