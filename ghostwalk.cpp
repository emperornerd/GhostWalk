/*
 * PROJECT: Ghost Walk
 * HARDWARE: ESP32 (WiFi Shield)
 * VERSION: 9.0 - "Forensic Compliance"
 * PURPOSE: High-density crowd simulation with strict generation/era enforcement.
 * Fixes "Double Header" bugs and "Time Travel" hardware anomalies.
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

// --- CONFIGURATION ---
#define ENABLE_PASSIVE_SCAN true      
#define ENABLE_SSID_REPLICATION true  
#define ENABLE_LIFECYCLE_SIM true     
#define ENABLE_SEQUENCE_GAPS true     
#define ENABLE_BEACON_EMULATION true
#define ENABLE_INTERACTION_SIM true   

// --- POOL SETTINGS ---
const int STATEFUL_POOL_SIZE = 1000;
const int DORMANT_POOL_SIZE = 2000;

// --- TRAFFIC TIMING ---
const int MIN_PACKETS_PER_HOP = 15;
const int MAX_PACKETS_PER_HOP = 40;
const int MIN_LIFECYCLE_MS = 3000;
const int MAX_LIFECYCLE_MS = 6000;
const int MIN_CHANNEL_HOP_MS = 150;
const int MAX_CHANNEL_HOP_MS = 350;

// --- POWER (Signal Strength) ---
const int8_t POWER_LEVELS[] = {74, 76, 78, 80, 82};
const int NUM_POWER_LEVELS = 5;
const int8_t JUNK_POWER_LEVELS[] = {60, 64, 68, 72, 74, 76};
const int NUM_JUNK_LEVELS = 6;

// --- DEVICE GENERATIONS ---
enum DeviceGen {
    GEN_LEGACY,      // 802.11n (WiFi 4) - 2.4GHz specific behavior
    GEN_COMMON,      // 802.11ac (WiFi 5)
    GEN_MODERN       // 802.11ax (WiFi 6)
};

enum OSPlatform {
    PLATFORM_IOS,
    PLATFORM_ANDROID,
    PLATFORM_OTHER   // IoT, Laptops, Legacy
};

// --- EXPANDED VENDOR OUIS (STRICT ERA MAPPING) ---

// Modern/Common Apple (iPhone/iPad/Mac)
const uint8_t OUI_APPLE[][3] = {
    {0xFC,0xFC,0x48}, {0xBC,0xD0,0x74}, {0xAC,0x1F,0x0F}, {0xF0,0xD4,0x15},
    {0xF0,0x98,0x9D}, {0x34,0x14,0x5F}, {0xDC,0xA9,0x04}, {0x28,0xCF,0xE9},
    {0xAC,0xBC,0x32}, {0xE4,0xCE,0x8F}, {0xBC,0x9F,0xEF}, {0x48,0x4B,0xAA},
    {0x88,0x66,0x5A}, {0x1C,0x91,0x48}, {0x60,0xFA,0xCD}
};

// Samsung (Galaxy S/Note/Tab)
const uint8_t OUI_SAMSUNG[][3] = {
    {0x24,0xFC,0xE5}, {0x8C,0x96,0xD4}, {0x5C,0xCB,0x99}, {0x34,0x21,0x09},
    {0x84,0x25,0xDB}, {0x00,0xE0,0x64}, {0x80,0xEA,0x96}, {0x38,0x01,0x95},
    {0xB0,0xC0,0x90}, {0xFC,0xC2,0xDE}
};

// Legacy IoT / Old Tech (Strictly for GEN_LEGACY)
// HP, Motorola, Nintendo, Texas Instruments
const uint8_t OUI_LEGACY_IOT[][3] = {
    {0x00,0x14,0x38}, {0x00,0x0D,0x93}, {0x00,0x1F,0x32}, {0x00,0x16,0x35},
    {0x00,0x04,0xBD}, {0x00,0x17,0xE0}, {0x00,0x1B,0x7A}
};

// Modern Generic (Intel, Google, Amazon)
const uint8_t OUI_MODERN_GEN[][3] = {
    {0x3C,0x5C,0x48}, {0x8C,0xF5,0xA3}, // Google
    {0x74,0xC6,0x3B}, {0xFC,0xA6,0x67}, // Amazon
    {0xE8,0x6A,0x64}, {0x60,0x55,0xF9}, // Intel AX
    {0xDC,0x8C,0x90}, {0x40,0x9F,0x38}  // AzureWave
};

// --- GLOBALS ---
TFT_eSPI tft = TFT_eSPI();

int currentChannel = 1;
unsigned long lastChannelHop = 0;
unsigned long lastLifecycleRun = 0;
unsigned long lastUiUpdateTime = 0;

unsigned long totalPacketCount = 0;
unsigned long learnedDataCount = 0;
unsigned long interactionCount = 0; 
unsigned long junkPacketCount = 0;

int nextChannelHopInterval = 250;
int nextLifecycleInterval = 3500;

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
};

std::vector<VirtualDevice> activeSwarm;
std::vector<VirtualDevice> dormantSwarm;
uint8_t packetBuffer[1024];
uint8_t noiseBuffer[256];

// --- SANITIZED PAYLOADS (NO HEADERS) ---
// Fix: Previous version included Tag ID and Length in array.
// These arrays now ONLY contain payload data.
const uint8_t HT_CAPS_PAYLOAD[] = {0xEF, 0x01, 0x1B, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t VHT_CAPS_PAYLOAD[] = {0x91, 0x59, 0x82, 0x0F, 0xEA, 0xFF, 0x00, 0x00, 0xEA, 0xFF, 0x00, 0x00};
// HE Caps (Payload only, no ExtID 35 yet)
const uint8_t HE_CAPS_PAYLOAD[] = {0x23, 0x09, 0x01, 0x00, 0x02, 0x40, 0x00, 0x04, 0x70, 0x0C, 0x89, 0x7F, 0x03, 0x80, 0x04, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA};

const uint8_t APPLE_VEND_PAYLOAD[] = {0x00, 0x17, 0xF2, 0x0A, 0x00, 0x01, 0x04};
const uint8_t WFA_VEND_PAYLOAD[] = {0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x1C, 0x00, 0x00};
const uint8_t RSN_PAYLOAD[] = {0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00};

// Distinct Rate Sets for Realism
const uint8_t RATES_LEGACY[] = {0x82, 0x84, 0x8b, 0x96}; 
const uint8_t RATES_MODERN[] = {0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24};

// --- FUNCTION DECLARATIONS ---
int addTag(uint8_t* buf, int ptr, uint8_t id, const uint8_t* data, int len);

// --- RESOURCE MANAGEMENT ---
void manageResources() {
    uint32_t freeHeap = ESP.getFreeHeap();
    if (freeHeap < 25000) {
        int activeDrop = activeSwarm.size() * 0.10;
        if (activeDrop > 0 && !activeSwarm.empty()) {
            activeSwarm.erase(activeSwarm.begin(), activeSwarm.begin() + activeDrop);
        }
        int dormantDrop = dormantSwarm.size() * 0.20;
        if (dormantDrop > 0 && !dormantSwarm.empty()) {
            dormantSwarm.erase(dormantSwarm.begin(), dormantSwarm.begin() + dormantDrop);
        }
        if (freeHeap < 15000 && activeSSIDs.size() > 15) {
            activeSSIDs.erase(activeSSIDs.begin(), activeSSIDs.begin() + 5);
        }
    }
}

// --- PASSIVE SCANNER ---
void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!ENABLE_PASSIVE_SCAN) return;
    if (type != WIFI_PKT_MGMT) return;
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* frame = pkt->payload;
    
    if (frame[0] != 0x40) return; // Only Probe Requests
    
    if (ENABLE_SSID_REPLICATION && activeSSIDs.size() < 100) {
        int pos = 24;
        if (frame[pos] == 0x00) {
            int len = frame[pos+1];
            if (len > 1 && len < 32) {
                char ssidBuf[33];
                memcpy(ssidBuf, &frame[pos+2], len);
                ssidBuf[len] = '\0';
                String ssidStr = String(ssidBuf);
                bool known = false;
                for (auto& s : activeSSIDs) { if (s.equals(ssidStr)) known = true; }
                if (!known) {
                    activeSSIDs.push_back(ssidStr);
                    learnedDataCount++;
                }
            }
        }
    }
}

// --- STRICT IDENTITY GENERATOR ---
void generateWeightedIdentity(VirtualDevice& vd) {
    int roll = random(100); // 0 - 99
    const uint8_t* selectedOUI;
    DeviceGen gen;
    OSPlatform plat;

    // STRICT ERA LOGIC:
    // Cannot assign Legacy OUI to Modern Gen.
    // Cannot assign Modern OUI to Legacy Gen (mostly).

    if (roll < 45) { // 45% APPLE
        selectedOUI = OUI_APPLE[random(15)];
        // Apple devices are rarely "Legacy" in the wild anymore, mostly AC or AX
        gen = (random(100) < 70) ? GEN_MODERN : GEN_COMMON; 
        plat = PLATFORM_IOS;
    } 
    else if (roll < 70) { // 25% SAMSUNG
        selectedOUI = OUI_SAMSUNG[random(10)];
        gen = (random(100) < 60) ? GEN_MODERN : GEN_COMMON; 
        plat = PLATFORM_ANDROID;
    }
    else if (roll < 85) { // 15% LEGACY IOT (Strict Mapping)
        selectedOUI = OUI_LEGACY_IOT[random(7)];
        gen = GEN_LEGACY; // FORCE Legacy
        plat = PLATFORM_OTHER;
    }
    else { // 15% MODERN GENERIC (Intel/Google)
        selectedOUI = OUI_MODERN_GEN[random(8)];
        gen = GEN_MODERN; // FORCE Modern
        plat = PLATFORM_ANDROID;
    }

    vd.generation = gen;
    vd.platform = plat;
    vd.hasConnected = false;

    // MAC RANDOMIZATION
    // Modern devices use private addressing more often
    bool usePrivate = (gen == GEN_MODERN && random(100) < 85) ||
                      (gen == GEN_COMMON && random(100) < 50);
    
    if (usePrivate) {
        vd.mac[0] = (random(256) & 0xFE) | 0x02; // Local bit set
        vd.mac[1] = random(256); vd.mac[2] = random(256);
    } else {
        vd.mac[0] = selectedOUI[0]; vd.mac[1] = selectedOUI[1]; vd.mac[2] = selectedOUI[2];
    }
    vd.mac[3] = random(256); vd.mac[4] = random(256); vd.mac[5] = random(256);
    
    vd.bssid_target[0] = 0x00; vd.bssid_target[1] = 0x11; vd.bssid_target[2] = 0x32;
    vd.bssid_target[3] = random(256); vd.bssid_target[4] = random(256); vd.bssid_target[5] = random(256);
    
    vd.sequenceNumber = random(4096);
    
    // PREFERRED SSID ASSIGNMENT
    // Modern devices scan less aggressively than legacy
    int probeChance = (gen == GEN_LEGACY) ? 90 : 60;
    vd.preferredSSIDIndex = (random(100) < probeChance && !activeSSIDs.empty()) ?
                            random(activeSSIDs.size()) : -1;
}

void initSwarm() {
    for (int i=0; i<NUM_SEED_SSIDS; i++) activeSSIDs.push_back(SEED_SSIDS[i]);
    activeSwarm.reserve(STATEFUL_POOL_SIZE);
    dormantSwarm.reserve(DORMANT_POOL_SIZE);
    for(int i=0; i<STATEFUL_POOL_SIZE; i++) {
        VirtualDevice vd;
        generateWeightedIdentity(vd);
        activeSwarm.push_back(vd);
    }
}

void processLifecycle() {
    if (!activeSwarm.empty()) {
        int idx = random(activeSwarm.size());
        VirtualDevice leaving = activeSwarm[idx];
        if (dormantSwarm.size() < DORMANT_POOL_SIZE) dormantSwarm.push_back(leaving);
        activeSwarm.erase(activeSwarm.begin() + idx);
    }
    VirtualDevice arriving;
    if (ENABLE_LIFECYCLE_SIM && !dormantSwarm.empty() && random(100) < 50) {
        int dIdx = random(dormantSwarm.size());
        arriving = dormantSwarm[dIdx];
        dormantSwarm.erase(dormantSwarm.begin() + dIdx);
        arriving.sequenceNumber = (arriving.sequenceNumber + random(50, 500)) % 4096;
        arriving.hasConnected = false;
    } else {
        generateWeightedIdentity(arriving);
    }
    activeSwarm.push_back(arriving);
}

// --- NOISE GENERATOR (SMART JUNK) ---
void fillSilenceWithNoise(unsigned long durationMs) {
    unsigned long start = millis();
    esp_wifi_set_max_tx_power(JUNK_POWER_LEVELS[random(NUM_JUNK_LEVELS)]);
    
    while (millis() - start < durationMs) {
        if (random(100) < 20) esp_wifi_set_max_tx_power(JUNK_POWER_LEVELS[random(NUM_JUNK_LEVELS)]);
        
        // Generate Temp Junk Identity
        uint8_t dummyMac[6];
        dummyMac[0] = (random(256) & 0xFE) | 0x02; 
        dummyMac[1] = random(256); dummyMac[2] = random(256);
        dummyMac[3] = random(256); dummyMac[4] = random(256); dummyMac[5] = random(256);

        noiseBuffer[0] = 0x40; // Probe Request
        noiseBuffer[1] = 0x00; noiseBuffer[2] = 0x00; noiseBuffer[3] = 0x00;
        memset(&noiseBuffer[4], 0xFF, 6);
        memcpy(&noiseBuffer[10], dummyMac, 6);
        memset(&noiseBuffer[16], 0xFF, 6);
        uint16_t seq = random(4096);
        noiseBuffer[22] = seq & 0xFF; noiseBuffer[23] = (seq >> 8) & 0xF0;
        
        // SMART NOISE SSID LOGIC:
        // Avoid 100% wildcard. Mix in random strings to look like "Hidden Network" checks.
        int ptr = 24;
        if (random(100) < 40) {
            // Fake "Hidden Network" check (Random String)
            int noiseLen = random(5, 12);
            noiseBuffer[ptr++] = 0x00; // Tag 0
            noiseBuffer[ptr++] = noiseLen;
            for(int x=0; x<noiseLen; x++) noiseBuffer[ptr++] = random(97, 122); 
        } else {
            // Wildcard (Traditional Noise)
            noiseBuffer[ptr++] = 0x00; noiseBuffer[ptr++] = 0x00;
        }

        // Minimal Tags for junk
        uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96};
        noiseBuffer[ptr++] = 0x01; noiseBuffer[ptr++] = 0x04;
        memcpy(&noiseBuffer[ptr], rates, 4); ptr += 4;

        esp_wifi_80211_tx(WIFI_IF_STA, noiseBuffer, ptr, false);
        totalPacketCount++;
        junkPacketCount++;
        yield();
    }
    esp_wifi_set_max_tx_power(POWER_LEVELS[random(NUM_POWER_LEVELS)]);
}

// --- PACKET BUILDERS ---

// Helper: Now purely appends TagID, Length, then Data
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
    
    // Rates based on Generation
    if (vd.generation == GEN_LEGACY) {
        ptr = addTag(buf, ptr, 0x01, RATES_LEGACY, sizeof(RATES_LEGACY));
    } else {
        ptr = addTag(buf, ptr, 0x01, RATES_MODERN, sizeof(RATES_MODERN));
    }
    
    ptr = addTag(buf, ptr, 48, RSN_PAYLOAD, sizeof(RSN_PAYLOAD));
    ptr = addTag(buf, ptr, 45, HT_CAPS_PAYLOAD, sizeof(HT_CAPS_PAYLOAD)); 
    if (vd.generation != GEN_LEGACY) ptr = addTag(buf, ptr, 191, VHT_CAPS_PAYLOAD, sizeof(VHT_CAPS_PAYLOAD));
    
    // Manual HE Tag construction for Extension ID
    if (vd.generation == GEN_MODERN) {
         buf[ptr++] = 255; // Ext Tag ID
         buf[ptr++] = sizeof(HE_CAPS_PAYLOAD) + 1;
         buf[ptr++] = 35; // HE Ext ID
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

// --- CORRECTED PROBE BUILDER ---
int buildProbePacket(uint8_t* buf, VirtualDevice& vd, int channel) {
    buf[0] = 0x40; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00;
    memset(&buf[4], 0xFF, 6); 
    memcpy(&buf[10], vd.mac, 6); 
    memset(&buf[16], 0xFF, 6);
    uint16_t seq = vd.sequenceNumber;
    buf[22] = seq & 0xFF; buf[23] = (seq >> 8) & 0xF0;
    int ptr = 24;

    // --- 1. SSID LOGIC (Fixing the Wildcard/Directed Tell) ---
    bool useWildcard = false;
    
    if (vd.generation == GEN_LEGACY || vd.platform == PLATFORM_OTHER) {
        // Legacy/IoT devices are allowed to Wildcard
        if (random(100) < 40) useWildcard = true;
    } else {
        // Modern devices (iOS/Android) ALMOST NEVER Wildcard in public.
        // They probe for specific known networks.
        useWildcard = false; 
    }

    if (useWildcard) {
        buf[ptr++] = 0x00; buf[ptr++] = 0x00; 
    } else {
        // If we must send directed, but have no preference, we fake a "Hidden Network" probe
        // or pick a random seed.
        String ssid;
        if (vd.preferredSSIDIndex != -1 && !activeSSIDs.empty()) {
            ssid = activeSSIDs[vd.preferredSSIDIndex];
        } else if (!activeSSIDs.empty()) {
             ssid = activeSSIDs[random(activeSSIDs.size())];
        } else {
             // Fallback if pool empty: Random String (looks like hidden net check)
             char temp[8];
             for(int i=0;i<7;i++) temp[i] = (char)random(97,122);
             temp[7]=0;
             ssid = String(temp);
        }
        
        buf[ptr++] = 0x00; buf[ptr++] = ssid.length();
        memcpy(&buf[ptr], ssid.c_str(), ssid.length()); ptr += ssid.length();
    }

    // --- 2. RATES (Generation Specific) ---
    if (vd.generation == GEN_LEGACY) {
        ptr = addTag(buf, ptr, 0x01, RATES_LEGACY, sizeof(RATES_LEGACY));
    } else {
        ptr = addTag(buf, ptr, 0x01, RATES_MODERN, sizeof(RATES_MODERN));
    }

    // --- 3. DS PARAM (Channel) ---
    buf[ptr++] = 0x03; buf[ptr++] = 0x01; buf[ptr++] = (uint8_t)channel;

    // --- 4. APPLE EXT CAP (Appears early on real devices) ---
    bool isApple = (vd.platform == PLATFORM_IOS);
    if (isApple) {
        uint8_t extCap[] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40};
        ptr = addTag(buf, ptr, 127, extCap, 8);
    }

    // --- 5. HT CAPS (All Gens) ---
    ptr = addTag(buf, ptr, 45, HT_CAPS_PAYLOAD, sizeof(HT_CAPS_PAYLOAD));

    // --- 6. VHT CAPS (WiFi 5/6) ---
    if (vd.generation != GEN_LEGACY) {
        ptr = addTag(buf, ptr, 191, VHT_CAPS_PAYLOAD, sizeof(VHT_CAPS_PAYLOAD));
    }

    // --- 7. NON-APPLE EXT CAP ---
    if (!isApple && vd.generation != GEN_LEGACY) {
        uint8_t extCapAnd[] = {0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40};
        ptr = addTag(buf, ptr, 127, extCapAnd, 8);
    }

    // --- 8. HE CAPS (WiFi 6 Only - Manual Construction) ---
    if (vd.generation == GEN_MODERN) {
         buf[ptr++] = 255; // Tag ID
         buf[ptr++] = sizeof(HE_CAPS_PAYLOAD) + 1; // Length + 1 for ExtID
         buf[ptr++] = 35; // Extension ID for HE Caps
         memcpy(&buf[ptr], HE_CAPS_PAYLOAD, sizeof(HE_CAPS_PAYLOAD));
         ptr += sizeof(HE_CAPS_PAYLOAD);
    }

    // --- 9. VENDOR SPECIFICS (Order Matters) ---
    // Standard WFA / MSFT often appear before Apple proprietary tags
    ptr = addTag(buf, ptr, 221, WFA_VEND_PAYLOAD, sizeof(WFA_VEND_PAYLOAD));
    
    // Apple Specific IE is usually last or near last
    if (isApple) {
        ptr = addTag(buf, ptr, 221, APPLE_VEND_PAYLOAD, sizeof(APPLE_VEND_PAYLOAD));
    }
    
    return ptr;
}

int buildBeaconPacket(uint8_t* buf, uint8_t* mac, const String& ssid, int channel, uint16_t seqNum) {
    buf[0] = 0x80; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00;
    memset(&buf[4], 0xFF, 6);
    memcpy(&buf[10], mac, 6); memcpy(&buf[16], mac, 6);
    buf[22] = seqNum & 0xFF; buf[23] = (seqNum >> 8) & 0xF0;
    int ptr = 24;
    memset(&buf[ptr], 0x00, 8); ptr += 8; // Timestamp
    buf[ptr++] = 0x64; buf[ptr++] = 0x00; // Interval
    buf[ptr++] = 0x31; buf[ptr++] = 0x04; // Cap Info
    buf[ptr++] = 0x00; buf[ptr++] = ssid.length();
    memcpy(&buf[ptr], ssid.c_str(), ssid.length()); ptr += ssid.length();
    ptr = addTag(buf, ptr, 0x01, RATES_LEGACY, sizeof(RATES_LEGACY));
    buf[ptr++] = 0x03; buf[ptr++] = 0x01; buf[ptr++] = (uint8_t)channel;
    return ptr;
}

// --- DISPLAY ---
void updateDisplayStats() {
    tft.fillRect(5, 110, 230, 120, TFT_BLACK); 
    tft.setTextSize(1);
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.setCursor(5, 110); tft.printf("--- TRAFFIC METRICS ---");
    
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.setCursor(5, 125); 
    tft.printf("RAM: %d KB | Active: %d", ESP.getFreeHeap()/1024, activeSwarm.size());
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setCursor(5, 140); tft.printf("Interact: %lu | Junk: %lu", interactionCount, junkPacketCount);
    
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.setCursor(5, 155);
    tft.printf("Total Pkts: %lu", totalPacketCount);
    tft.setCursor(5, 170); 
    tft.setTextColor(TFT_CYAN, TFT_BLACK);
    tft.printf("Mode: ERA ENFORCED");
}

void setupDisplay() {
  tft.init();
  tft.setRotation(1); tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_ORANGE, TFT_BLACK); tft.setTextSize(2);
  tft.setCursor(5, 5);
  tft.println("GHOST WALK v9"); 
  tft.drawRect(0, 0, tft.width(), tft.height(), TFT_DARKGREY);
  tft.setTextSize(1);
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  tft.setCursor(5, 30); tft.printf("Strict Gen: ENABLED");
  tft.setCursor(5, 42); tft.printf("Apple Fix: APPLIED");
  updateDisplayStats();
}

void setup() {
  Serial.begin(115200);
  uint8_t mac_base[6];
  esp_read_mac(mac_base, ESP_MAC_WIFI_STA);
  randomSeed(analogRead(0) * micros() + mac_base[5]);
  
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
  esp_wifi_set_max_tx_power(POWER_LEVELS[0]);

  nextChannelHopInterval = random(MIN_CHANNEL_HOP_MS, MAX_CHANNEL_HOP_MS);
  nextLifecycleInterval = random(MIN_LIFECYCLE_MS, MAX_LIFECYCLE_MS);
  
  initSwarm();
}

void loop() {
  manageResources();

  unsigned long currentMillis = millis();

  if (currentMillis - lastLifecycleRun > nextLifecycleInterval) {
      lastLifecycleRun = currentMillis;
      nextLifecycleInterval = random(MIN_LIFECYCLE_MS, MAX_LIFECYCLE_MS);
      int rotateCount = random(3, 8);
      for(int i=0; i<rotateCount; i++) processLifecycle();
  }

  if (currentMillis - lastChannelHop > nextChannelHopInterval) {
    lastChannelHop = currentMillis;
    nextChannelHopInterval = random(MIN_CHANNEL_HOP_MS, MAX_CHANNEL_HOP_MS);
    
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    int packetsThisHop = random(MIN_PACKETS_PER_HOP, MAX_PACKETS_PER_HOP);

    for (int i = 0; i < packetsThisHop; i++) {
        if (!activeSwarm.empty()) {
            int swarmIdx = random(activeSwarm.size());
            VirtualDevice& vd = activeSwarm[swarmIdx];
            int pktLen = 0;

            if (ENABLE_INTERACTION_SIM && random(100) < 2 && vd.preferredSSIDIndex != -1) {
                 String targetSSID = activeSSIDs[vd.preferredSSIDIndex];
                 vd.hasConnected = true;
                 
                 pktLen = buildAuthPacket(packetBuffer, vd);
                 esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
                 vd.sequenceNumber = (vd.sequenceNumber + 1) % 4096;
                 fillSilenceWithNoise(random(10, 40));

                 pktLen = buildAssocRequestPacket(packetBuffer, vd, targetSSID);
                 esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
                 vd.sequenceNumber = (vd.sequenceNumber + 1) % 4096;
                 fillSilenceWithNoise(random(30, 100));

                 int burstCount = random(3, 12);
                 for(int b=0; b<burstCount; b++) {
                     pktLen = buildEncryptedDataPacket(packetBuffer, vd);
                     esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
                     vd.sequenceNumber = (vd.sequenceNumber + 1) % 4096;
                     totalPacketCount++;
                     fillSilenceWithNoise(random(5, 20));
                 }
                 interactionCount++;
            }
            else {
                pktLen = buildProbePacket(packetBuffer, vd, currentChannel);
                esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
                if (pktLen > 0) {
                    totalPacketCount++;
                    int step = (ENABLE_SEQUENCE_GAPS && random(100) < 20) ? random(2, 8) : 1;
                    vd.sequenceNumber = (vd.sequenceNumber + step) % 4096;
                }
            }
        }
        
        if (ENABLE_BEACON_EMULATION && random(100) < 35 && !activeSSIDs.empty()) {
            int ssidIdx = random(activeSSIDs.size());
            String beaconSSID = activeSSIDs[ssidIdx];
            uint8_t mac[6]; 
            mac[0] = 0x00; mac[1] = 0x11; mac[2] = 0x22; 
            mac[3] = random(255); mac[4] = random(255); mac[5] = random(255);
            int pktLen = buildBeaconPacket(packetBuffer, mac, beaconSSID, currentChannel, random(4096));
            esp_wifi_80211_tx(WIFI_IF_STA, packetBuffer, pktLen, false);
            totalPacketCount++;
        }

        fillSilenceWithNoise(random(2, 10));
    }
  }
  
  if (currentMillis - lastUiUpdateTime > 2500) {
      lastUiUpdateTime = currentMillis;
      updateDisplayStats();
  }
}
