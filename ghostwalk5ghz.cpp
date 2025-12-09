/*
 * PROJECT: Ghost Walk
 * HARDWARE: ESP32 (WiFi Shield) / ESP32-C5 (Dual Band)
 * VERSION: 9.3.3 - "Forensic Compliance"
 * PURPOSE: High-density crowd simulation with forensic hardening.
 * FEATURES: Interleaved Dual-Band Hopping, Sticky RSSI, HT/VHT Beacons.
 * UPDATE: Reverted Noise MACs to Private, Fixed 2.4GHz HT Beacon compliance.
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_system.h>
#include <esp_wifi_types.h> 
#include <esp_mac.h> 
#include <vector>
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

// --- POOL SETTINGS ---
// Note: These are "Soft Caps". If RAM is low, the system will auto-reduce.
const int TARGET_ACTIVE_POOL = 1500;
const int TARGET_DORMANT_POOL = 3000;

// --- TRAFFIC TIMING ---
const int MIN_PACKETS_PER_HOP = 20; 
const int MAX_PACKETS_PER_HOP = 45;
// CHANGED: MIN/MAX LIFECYCLE MS used for faster processing (x0.66)
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
    {0x24,0xFC,0xE5}, {0x8C,0x96,0xD4}, {0x5C,0xCB,0x99}, {0x34,0x21,0x09},
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

struct SniffedSSID {
    char ssid[33];
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

unsigned long totalPacketCount = 0;
unsigned long learnedDataCount = 0;
unsigned long interactionCount = 0; 
unsigned long junkPacketCount = 0;
String lastLearnedSSID = "None";

// Stats for TFT
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
const uint8_t WFA_VEND_PAYLOAD[] = {0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x1C, 0x00, 0x00};
const uint8_t RSN_PAYLOAD[] = {0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00};

// Rates
const uint8_t RATES_LEGACY[] = {0x82, 0x84, 0x8b, 0x96}; 
const uint8_t RATES_MODERN_2G[] = {0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24}; 
const uint8_t RATES_5G[] = {0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c};

// --- FUNCTION DECLARATIONS ---
int addTag(uint8_t* buf, int ptr, uint8_t id, const uint8_t* data, int len);

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

// --- PASSIVE SCANNER (THREAD SAFE) ---
void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!ENABLE_PASSIVE_SCAN) return;
    if (type != WIFI_PKT_MGMT) return;
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* frame = pkt->payload;
    
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

// --- STRICT IDENTITY GENERATOR (UPDATED DEMOGRAPHICS) ---
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

    bool usePrivate = (gen == GEN_MODERN && random(100) < 85) ||
                      (gen == GEN_COMMON && random(100) < 50);
    
    if (usePrivate) {
        vd.mac[0] = (random(256) & 0xFE) | 0x02; 
        vd.mac[1] = random(256); vd.mac[2] = random(256);
    } else {
        vd.mac[0] = selectedOUI[0]; vd.mac[1] = selectedOUI[1]; vd.mac[2] = selectedOUI[2];
    }
    vd.mac[3] = random(256); vd.mac[4] = random(256); vd.mac[5] = random(256);
    
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
    // MEMORY GUARD: If low memory, do NOT add new agents, effectively shrinking the pool.
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

// --- NOISE GENERATOR (REVERTED) ---
void fillSilenceWithNoise(unsigned long durationMs) {
    unsigned long start = millis();
    // Noise power floor
    int noisePower = 68 + random(0, 6); 
    esp_wifi_set_max_tx_power(noisePower); 
    
    while (millis() - start < durationMs) {
        uint8_t noiseMac[6];
        
        // --- REVERTED JUNK MAC LOGIC ---
        // Uses Locally Administered Random MACs (Private) to simulate background randomization
        // rather than using valid OUIs which can appear as "spoofed" or fake devices.
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

int addTag(uint8_t* buf, int ptr, uint8_t id, const uint8_t* data, int len) {
    buf[ptr++] = id;
    buf[ptr++] = len;
    memcpy(&buf[ptr], data, len);
    return ptr + len;
}

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
    // FIXED: HT Operation (Tag 61) is now added for both 2.4GHz and 5GHz.
    // This ensures 2.4GHz Beacons appear as 802.11n (WiFi 4) rather than Legacy 802.11g.
    uint8_t htOp[] = {(uint8_t)channel, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
    ptr = addTag(buf, ptr, 61, htOp, 22);

    // VHT Operation (Tag 192) remains 5GHz specific (802.11ac)
    if (is5GHzBand) {
         uint8_t vhtOp[] = {0x00, 0x00, 0x00, 0x00, 0x00};
         ptr = addTag(buf, ptr, 192, vhtOp, 5);
    }
    
    return ptr;
}

// --- DISPLAY ---
void updateDisplayStats() {
    tft.fillRect(5, 60, 230, 150, TFT_BLACK); 
    tft.setTextSize(1);
    
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.setCursor(5, 70); tft.printf("--- TRAFFIC METRICS ---"); 
    
    if (lowMemoryMode) tft.setTextColor(TFT_RED, TFT_BLACK);
    else tft.setTextColor(TFT_GREEN, TFT_BLACK);
    
    tft.setCursor(5, 85); 
    tft.printf("Free RAM: %d KB %s", ESP.getFreeHeap()/1024, lowMemoryMode ? "[LOW]" : ""); 
    
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.setCursor(5, 97);
    tft.printf("Active: %d | Dormant: %d", activeSwarm.size(), dormantSwarm.size());
    
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setCursor(5, 109); 
    tft.printf("Total Packets: %lu", totalPacketCount);
    tft.setCursor(5, 121);
    tft.printf("Noise/Junk: %lu", junkPacketCount);

    unsigned long total = packets2G + packets5G;
    int p2g = (total > 0) ? (packets2G * 100 / total) : 0;
    int p5g = (total > 0) ? (packets5G * 100 / total) : 0;
    
    tft.setTextColor(TFT_CYAN, TFT_BLACK);
    tft.setCursor(5, 135);
    tft.printf("Band: 2.4G[%d%%] 5G[%d%%]", p2g, p5g);

    tft.setTextColor(TFT_ORANGE, TFT_BLACK);
    tft.setCursor(5, 147);
    tft.printf("Found SSIDs: %lu", learnedDataCount);
    
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.setCursor(5, 159);
    String truncSSID = lastLearnedSSID;
    if (truncSSID.length() > 22) truncSSID = truncSSID.substring(0, 22) + "...";
    tft.printf("Last: %s", truncSSID.c_str());
    
    unsigned long upSec = (millis() - startTime) / 1000;
    int hr = upSec / 3600;
    int mn = (upSec % 3600) / 60;
    int sc = upSec % 60;
    
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.setCursor(5, 175); 
    tft.printf("Uptime: %02d:%02d:%02d", hr, mn, sc);

    tft.setCursor(5, 195); 
    if (HARDWARE_IS_C5) {
        tft.setTextColor(TFT_MAGENTA, TFT_BLACK);
        if (is5GHzBand) tft.printf("RADIO: 5GHz [ACTIVE]");
        else tft.printf("RADIO: 2.4GHz [ACTIVE]");
    } else {
        tft.setTextColor(TFT_CYAN, TFT_BLACK);
        tft.printf("RADIO: 2.4GHz [ONLY]");
    }
}

void setupDisplay() {
  tft.init();
  tft.setRotation(1); tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_ORANGE, TFT_BLACK); tft.setTextSize(2);
  tft.setCursor(5, 5);
  tft.println("GHOST WALK v9.3.3"); 
  tft.drawRect(0, 0, tft.width(), tft.height(), TFT_DARKGREY);
  tft.setTextSize(1);
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  
  tft.setCursor(5, 30); 
  if (HARDWARE_IS_C5) tft.printf("Mode: INTERLEAVED");
  else tft.printf("Mode: 2.4GHz LINEAR");
  
  tft.setCursor(5, 42); 
  if (HARDWARE_IS_C5) tft.printf("HW: ESP32-C5 (Dual)");
  else tft.printf("HW: Standard (2.4G)");
  
  updateDisplayStats();
}

void setup() {
  Serial.begin(115200);
  
  ssidQueue = xQueueCreate(20, sizeof(SniffedSSID));

  uint8_t mac_base[6];
  esp_read_mac(mac_base, ESP_MAC_WIFI_STA);
  randomSeed(analogRead(0) * micros() + mac_base[5]);
  startTime = millis();
  
  setupDisplay();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  if (esp_wifi_init(&cfg) != ESP_OK) while(1);
  
  if (ENABLE_PASSIVE_SCAN) {
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(snifferCallback);
  }
  
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  esp_wifi_set_max_tx_power(POWER_LEVELS[4]); 

  initSwarm();
}

void loop() {
  SniffedSSID s;
  while (xQueueReceive(ssidQueue, &s, 0) == pdTRUE) {
      if (ENABLE_SSID_REPLICATION && activeSSIDs.size() < 100 && !lowMemoryMode) {
          String newSSID = String(s.ssid);
          bool known = false;
          for (auto& existing : activeSSIDs) {
              if (existing.equals(newSSID)) {
                  known = true;
                  break;
              }
          }
          if (!known) {
              activeSSIDs.push_back(newSSID);
              learnedDataCount++;
              lastLearnedSSID = newSSID;
          }
      }
  }

  manageResources();

  unsigned long currentMillis = millis();

  if (currentMillis - lastLifecycleRun > nextLifecycleInterval) {
      lastLifecycleRun = currentMillis;
      // MODIFIED: Lifecycle interval reduced by 34% (1.5x speed)
      nextLifecycleInterval = random(MIN_LIFECYCLE_MS * 66 / 100, MAX_LIFECYCLE_MS * 66 / 100); 
      int rotateCount = random(3, 8);
      for(int i=0; i<rotateCount; i++) processLifecycle();
  }

  if (currentMillis - lastChannelHop > nextChannelHopInterval) {
    lastChannelHop = currentMillis;
    nextChannelHopInterval = random(MIN_CHANNEL_HOP_MS, MAX_CHANNEL_HOP_MS);
    
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
                 
                 // MODIFIED: Reduced junk packet duration by 25-50%
                 fillSilenceWithNoise(random(10 * 75 / 100, 40 * 50 / 100)); 

                 pktLen = buildAssocRequestPacket(packetBuffer, vd, targetSSID);
                 esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
                 vd.sequenceNumber = (vd.sequenceNumber + 1) % 4096;
                 
                 // MODIFIED: Reduced junk packet duration by 25-50%
                 fillSilenceWithNoise(random(30 * 75 / 100, 100 * 50 / 100));

                 int burstCount = random(3, 12);
                 for(int b=0; b<burstCount; b++) {
                     pktLen = buildEncryptedDataPacket(packetBuffer, vd);
                     esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
                     vd.sequenceNumber = (vd.sequenceNumber + 1) % 4096;
                     totalPacketCount++;
                     if (is5GHzBand) packets5G++; else packets2G++;
                     // MODIFIED: Reduced junk packet duration by 25-50%
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
        
        // MODIFIED: Router traffic reduced to 2% (from 35%)
        if (ENABLE_BEACON_EMULATION && random(100) < 2 && !activeSSIDs.empty()) {
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

        // MODIFIED: Reduced junk packet duration by 25-50%
        fillSilenceWithNoise(random(2 * 75 / 100, 10 * 50 / 100));
    }
  }
  
  if (currentMillis - lastUiUpdateTime > 2000) {
      lastUiUpdateTime = currentMillis;
      updateDisplayStats();
  }
}