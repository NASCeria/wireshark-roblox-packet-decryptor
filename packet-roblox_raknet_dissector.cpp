// written by nasec(@mrnasec) ages ago (about like 2025 august)
// beware, explicit language + degeneracy + racism c:
// also some stuff is stripped cuz no leaky leaky!

#include "config.h"
#include <epan/packet.h>

#include <Windows.h>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <epan/conversation.h>
#include <epan/proto_data.h>

#include "roblox.hpp"

extern "C"
{
#include "memory_bridge.h"

}


#include <sodium.h>


// Deserialization Helpers

#define BITS_TO_BYTES(x) (((x)+7)>>3)
#define BYTES_TO_BITS(x) ((x)<<3)


bool niggamode;


// Raknet::Bitstream
struct __declspec(align(8)) BitStream
{
public:
    bool isJoinData;					//0x8

    // BitStream
    uint32_t numberOfBitsUsed;			//0x10
    uint32_t numberOfBitsAllocated;
    uint32_t readOffset;

    char padding1[8];

    unsigned char* data;				//0x20
    bool copyData;

    unsigned char stackData[256];		//0x29


    inline void AlignReadToByteBoundary(void) { readOffset += 8 - (((readOffset - 1) & 7) + 1); }

    bool ReadBits(unsigned char* inOutByteArray, uint32_t numberOfBitsToRead, const bool alignBitsToRight)
    {
        if(!inOutByteArray)
            return false;

        if (numberOfBitsToRead <= 0)
            return false;

        if (readOffset + numberOfBitsToRead > numberOfBitsUsed)
            return false;


        const uint32_t readOffsetMod8 = readOffset & 7;

        // If currently aligned and numberOfBits is a multiple of 8, just memcpy for speed
        if (readOffsetMod8 == 0 && (numberOfBitsToRead & 7) == 0)
        {
            memcpy(inOutByteArray, data + (readOffset >> 3), numberOfBitsToRead >> 3);
            readOffset += numberOfBitsToRead;
            return true;
        }

        uint32_t offset = 0;

        memset(inOutByteArray, 0, (size_t)BITS_TO_BYTES(numberOfBitsToRead));

        while (numberOfBitsToRead > 0)
        {
            *(inOutByteArray + offset) |= *(data + (readOffset >> 3)) << (readOffsetMod8); // First half

            if (readOffsetMod8 > 0 && numberOfBitsToRead > 8 - (readOffsetMod8))   // If we have a second half, we didn't read enough bytes in the first half
                *(inOutByteArray + offset) |= *(data + (readOffset >> 3) + 1) >> (8 - (readOffsetMod8)); // Second half (overlaps byte boundary)

            if (numberOfBitsToRead >= 8)
            {
                numberOfBitsToRead -= 8;
                readOffset += 8;
                offset++;
            }
            else
            {
                int neg = (int)numberOfBitsToRead - 8;

                if (neg < 0)   // Reading a partial byte for the last byte, shift right so the data is aligned on the right
                {

                    if (alignBitsToRight)
                        *(inOutByteArray + offset) >>= -neg;

                    readOffset += 8 + neg;
                }
                else
                    readOffset += 8;

                offset++;

                numberOfBitsToRead = 0;
            }
        }

        return true;
    }

    inline bool Read(bool& outTemplateVar)
    {
        if (readOffset + 1 > numberOfBitsUsed)
            return false;

        if (data[readOffset >> 3] & (0x80 >> (readOffset & 7)))   // Is it faster to just write it out here?
            outTemplateVar = true;
        else
            outTemplateVar = false;

        // Has to be on a different line for Mac
        readOffset++;

        return true;
    }

    void ReverseBytes(unsigned char* inByteArray, unsigned char* inOutByteArray, const unsigned int length)
    {
        for (uint32_t i = 0; i < length; i++)
            inOutByteArray[i] = inByteArray[length - i - 1];
    }

    inline bool ReadFloat(float& outTemplateVar)
    {
        unsigned char output[4];
        if (ReadBits((unsigned char*)output, 4 * 8, true))
        {
            ReverseBytes(output, (unsigned char*)&outTemplateVar, 4);
            return true;
        }
        return false;
    }

    inline bool ReadUint24(uint32_t& outTemplateVar)
    {
        uint32_t output;
        ZeroMemory(&output, 4);

        if (ReadBits((unsigned char*)&output, 3 * 8, true))
        {
            outTemplateVar = output;//(output[0] << 16) | (output[1] << 8) | output[2];
            return true;
        }
        return false;
    }

    inline bool ReadUint32(uint32_t& outTemplateVar)
    {
        unsigned char output[4];
        if (ReadBits((unsigned char*)output, 4 * 8, true))
        {
            ReverseBytes(output, (unsigned char*)&outTemplateVar, 4);
            return true;
        }
        return false;
    }

    inline bool ReadUint16(uint16_t& outTemplateVar)
    {
        unsigned char output[2];
        if (ReadBits((unsigned char*)output, 2 * 8, true))
        {
            ReverseBytes(output, (unsigned char*)&outTemplateVar, 2);
            return true;
        }
        return false;
    }

    inline bool ReadShort(unsigned short& outTemplateVar)
    {
        unsigned char output[2];
        if (ReadBits((unsigned char*)output, 2 * 8, true))
        {
            ReverseBytes(output, (unsigned char*)&outTemplateVar, 2);
            return true;
        }
        return false;
    }

    BitStream(unsigned char* Data, uint32_t size)
    {
        this->data = Data;
        this->numberOfBitsUsed = size * 8;
        this->numberOfBitsAllocated = size * 8;
        this->readOffset = 0;
    }
};

// RBX::Network::NetworkStream
struct NetworkStream
{
    unsigned char* data;
    std::vector<unsigned char> dataVector;

    uint32_t numberOfBytesUsed = 0;
    uint32_t numberOfBytesAllocated = 0;
    uint32_t readOffset = 0;
    bool ownedData = 0;

    inline int GetReadOffset()
    {
        return readOffset;
    }

    inline void SetReadOffset(int ReadOffset)
    {
        readOffset = ReadOffset;
    }

    inline void IgnoreBytes(int Size)
    {
        readOffset += Size;
    }

    inline unsigned char* ReadBytes(uint8_t size)
    {
        unsigned int oldOffset = this->GetReadOffset();
        this->SetReadOffset(oldOffset + size);

        return data + oldOffset;
    }

    inline unsigned char* Read(uint8_t size)
    {
        return ReadBytes(size);
    }

    inline uint32_t ReadUint24(bool bigEndian = false)
    {
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(ReadBytes(3));

        if (bigEndian) {
            return (bytes[0] << 16) | (bytes[1] << 8) | bytes[2];
        }
        else {
            return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16);
        }
    }

    template<typename T>
    inline T Read(bool bigEndian = false)
    {
        T result = *(T*)ReadBytes(sizeof(T));

        if (bigEndian && sizeof(T) > 1)
        {
            char* bytes = reinterpret_cast<char*>(&result);
            for (unsigned int i = 0; i < sizeof(T) / 2; i++) __pragma(warning(suppress:6294))
            {
                std::swap(bytes[i], bytes[sizeof(T) - 1 - i]);
            }
        }

        return result;
    }

    inline void WriteBytes(const void* src, int size)
    {
        unsigned int oldOffset = this->GetReadOffset();
        this->SetReadOffset(oldOffset + size);

        if (this->numberOfBytesAllocated <= oldOffset + size)
        {
            // Reallocate!!
            dataVector.resize(oldOffset + size);
            this->numberOfBytesAllocated = (uint32_t)dataVector.capacity();
            data = dataVector.data();
        }

        this->numberOfBytesUsed += size;

        memcpy(data + oldOffset, src, size);
    }

    template<typename T>
    inline void Write(T Value, bool bigEndian = false)
    {
        void* src = &Value;

        if (bigEndian)
        {
            char* bytes = reinterpret_cast<char*>(src);
            for (size_t i = 0; i < sizeof(T) / 2; i++) {
                std::swap(bytes[i], bytes[sizeof(T) - 1 - i]);
            }
        }

        WriteBytes(src, sizeof(T));
    }

    inline void WriteVarInt(UINT64 Value)
    {
        bool firstIteration = true;
        for (size_t i = 0; i < 8; i++)
        {
            if (!firstIteration && !Value)
                break;
            firstIteration = false;

            UINT8 val = Value & 0x7F;
            Value >>= 7;

            UINT8 newVal = val | 0x80;
            if (!Value)
                newVal = val;

            WriteBytes(&newVal, 1);
        }
    }

    void WriteString(const std::string& String)
    {
        WriteVarInt(String.length());
        WriteBytes(String.data(), (int)String.length());
    }

    void Append(NetworkStream* Stream)
    {
        WriteBytes(Stream->data, Stream->numberOfBytesUsed); // TODO: maybe readOffset it?
    }

    inline void Dump(FILE* File)
    {
        fprintf(File, "NetworkStream Dump: %u bytes used\n", numberOfBytesUsed);
        for (uint32_t i = 0; i < numberOfBytesUsed; i++)
        {
            fprintf(File, "%02x ", data[i]);
        }
        fprintf(File, " \n");
    }

    NetworkStream(unsigned char* Data, uint32_t size, bool copyData = false)
    {

        this->readOffset = 0;
        this->ownedData = copyData;
        this->data = Data;
        if (copyData)
        {
            this->dataVector = std::vector<unsigned char>(Data, Data + size);
            this->data = dataVector.data();
        }
        this->numberOfBytesUsed = size;
        this->numberOfBytesAllocated = (uint32_t)dataVector.size();
    }

    ~NetworkStream()
    { }
};

// Raknet Definitions

static const unsigned char RAKNET_OFFLINE_MESSAGE_DATA_ID[] = { 0x0, 0xff, 0xff, 0x0, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78 };

enum RakNet_PacketReliability : uint8_t
{
    UNRELIABLE,
    UNRELIABLE_SEQUENCED,
    RELIABLE,
    RELIABLE_ORDERED,
    RELIABLE_SEQUENCED,
    UNRELIABLE_WITH_ACK_RECEIPT,
    RELIABLE_WITH_ACK_RECEIPT,
    RELIABLE_ORDERED_WITH_ACK_RECEIPT,
    NUMBER_OF_RELIABILITIES
};

enum RakNet_PacketPriority : uint32_t
{
    IMMEDIATE_PRIORITY = 0x0,
    HIGH_PRIORITY = 0x1,
    MEDIUM_PRIORITY = 0x2,
    LOW_PRIORITY = 0x3,
    NUMBER_OF_PRIORITIES = 0x4,
};

enum Roblox_PacketId : uint8_t
{
    // TODO: Raknet Packets need to be impl'd too
    ID_TIMESTAMP = 0x1B,

    // Roblox Packets
    ID_DATA = 0x83,
    ID_CLUSTER = 0x8D,
    ID_PHYSICS_TOUCHES = 0x86,
    ID_CHAT_ALL = 0x87,
};

enum ItemType : uint8_t
{
    PingItem = 5,
    PingBackItem = 6,
    EventInvocationItem = 7,
};

// Roblox Definitions

stripped

// Dissector

static int proto_foo;

static dissector_handle_t foo_handle;

static int hf_ronet_reliability;
static int hf_ronet_datagramNumber;
static int hf_ronet_isValid;
static int hf_ronet_isAck;
static int hf_ronet_isIngoing;
static int hf_ronet_isNack;
static int hf_ronet_isJoindata;
static int hf_ronet_isSplitPacket;
static int hf_ronet_decrypted_payload;
static int hf_ronet_user_payload;

static int hf_ronet_isPingItem;
static int hf_ronet_detectionFlags;



static int ett_ronet;
static int ett_ronet_datagram;
static int ett_ronet_internalPacket;
static int ett_ronet_roblox;


static bool
deserialize_rupp_header(BitStream* Stream)
{
    uint8_t protocol;
    Stream->ReadBits(&protocol, 8, false);

    if (protocol != 1) // 1 = RakNet
        return false;

    uint8_t flags;
    Stream->ReadBits(&flags, 8, false); // Flags

    uint16_t headerLength;
    Stream->ReadShort(headerLength);

    Stream->readOffset = BYTES_TO_BITS(headerLength);

    return true;
}

static bool
deserialize_rupp_header(NetworkStream* Stream)
{
    uint8_t protocol = Stream->Read<uint8_t>();

    if (protocol != 1) // 1 = RakNet
        return false;

    uint8_t flags = Stream->Read<uint8_t>(); _U_ // Flags

    uint16_t headerLength = Stream->Read<uint16_t>(true); // header Length

    Stream->readOffset = headerLength;

    return true;
}

bool ruppMode = false;

static bool
test_offline_message(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    if (tvb_memeql(tvb, 1, RAKNET_OFFLINE_MESSAGE_DATA_ID, sizeof(RAKNET_OFFLINE_MESSAGE_DATA_ID)) == 0)
    {
        // ID_OPEN_CONNECTION_REQUEST_1
        return true;
    }

    // Maybe ruppHeader?

    
    BitStream stream((unsigned char*)tvb_get_ptr(tvb, 0, tvb_reported_length(tvb)), tvb_reported_length(tvb));

    if (deserialize_rupp_header(&stream))
    {
        unsigned char possibleOffline[sizeof(RAKNET_OFFLINE_MESSAGE_DATA_ID) + 1];

        stream.ReadBits(possibleOffline, BYTES_TO_BITS(sizeof(possibleOffline)), false);

        if (memcmp(possibleOffline + 1, RAKNET_OFFLINE_MESSAGE_DATA_ID, sizeof(RAKNET_OFFLINE_MESSAGE_DATA_ID)) == 0)
        {
            printf("Enabled rupp mode");
            ruppMode = true;
            return true;
        }
    }
    
    return false;
}

struct DatagramHeaderFormat
{
    unsigned __int64 sourceSystemTime;
    uint32_t datagramNumber;
    float AS;
    bool isACK;
    bool isNAK;
    bool hasBAndAS;
    bool isContinuousSend;
    bool needsBAndAs;
    bool isValid;
    bool hasAckTimestamps;
    unsigned __int16 extraPadding;
    bool isJoinData;
    bool isResentData;
};

// Roblox can change those at any time since they are controlled via fflags
static const long long commonCapabilities = 0x2C000BBFAFA;

void
DeserializeDatagramHeader(BitStream* bitStream, DatagramHeaderFormat* Header)
{
    bitStream->Read(Header->isValid);
    bitStream->Read(Header->isACK);

    if (Header->isACK)
    {
        Header->isNAK = 0;

        bitStream->Read(Header->hasBAndAS);
        bitStream->Read(Header->hasAckTimestamps);
        bitStream->AlignReadToByteBoundary();

        if(Header->hasBAndAS)
        {
            bitStream->ReadFloat(Header->AS);
        }

        if ((commonCapabilities & 0x80) == 0)
        {
            bitStream->ReadShort(Header->extraPadding);
        }
    }
    else
    {
        bitStream->Read(Header->isNAK);

        if (Header->isNAK)
        {
            bitStream->AlignReadToByteBoundary();
            if ((commonCapabilities & 0x80) == 0)
            {
                bitStream->ReadShort(Header->extraPadding);
            }

            return;
        }

        if (commonCapabilities & 0x200000)
        {
            bitStream->Read(Header->isJoinData);
        }

        if (commonCapabilities & 0x800000)
        {
            bitStream->Read(Header->isResentData);
        }

        bitStream->readOffset += 1; // Idk. 

        bitStream->Read(Header->isContinuousSend);
        bitStream->Read(Header->needsBAndAs);
        bitStream->AlignReadToByteBoundary();

        bitStream->ReadUint24(Header->datagramNumber);

        if((commonCapabilities & 0x80) == 0)
        {
            bitStream->ReadShort(Header->extraPadding);

            bitStream->readOffset = bitStream->numberOfBitsUsed - 8 * Header->extraPadding;
        }
    }

    return;
}

static bool
dissect_ronet_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    if(niggamode)
        return false;

    if (test_offline_message(tvb, pinfo, tree, data)) {
        conversation_t* conversation;

        conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, foo_handle);

        return call_dissector_only(foo_handle, tvb, pinfo, tree, data) > 0;
    }
    else {
        return false;
    }
}


// Roblox Bridge Attempt
unsigned char keys[0x20] = { 0x91, 0x2C, 0xCB, 0xC1, 0x98, 0xBE, 0xAB, 0x0C, 0x75, 0x69, 0xC8, 0x47, 0xD9, 0x18, 0xAF, 0xD0, 0x46, 0x69, 0x3D, 0xE5, 0x29, 0x7A, 0xEC, 0xEB, 0x16, 0x04, 0x59, 0x06, 0x13, 0x91, 0x19, 0xC5};

unsigned char client_tx_key[0x20] = {};
unsigned char client_rx_key[0x20] = {};

// 8452805105709313621 = UniqueNu
uint64_t client_txnonce = 8452805105709313621; // increases by 1 for each packet transmitted
uint64_t client_rxnonce = 8452805105709313621; // increases by 1 for each packet received

attached_process* roblox_process = 0;
rbx_rakpeercrypto* rakpeer_crypto = 0;

int sourcePort = 0;

void
create_roblox_bridge(bool studio = true)
{
    attached_process* proc = mem_attachx(studio ? "RobloxStudioBeta.exe" : "RobloxPlayerBeta.exe");
    roblox_process = proc;

    rbx_instance* datamodel = rbx_getdatamodel(proc);

    g_print("DataModel at %p\n", datamodel);

    rbx_instance* inst = rbx_findfirstchild(proc, datamodel, "NetworkClient");
    inst = rbx_findfirstchild(proc, inst, "ClientReplicator");

    g_print("ClientReplicator is at %p\n", inst);

    rakpeer_crypto = rbx_getrakpeercrypto(proc, inst);

    g_print("RakPeerCrypto is at %p\n", rakpeer_crypto);
}

static int
decrypt_roblox_packet(unsigned char* packet,int len, char format)
{
    // yes yes nasec writes goooooooood cleaaaaannn codeeeee
    unsigned char* header = &packet[len - 18];
    unsigned char pubkey[12];
    memcpy(pubkey, "UniqueNumbeR", 12);

    UINT16 recvNonce = *(UINT16*)header;

    uintptr_t lalasex = recvNonce | client_txnonce & 0xFFFFFFFFFFFF0000uLL;

    uintptr_t lalasexoo = recvNonce - (client_txnonce & 0xFFFFuLL);

    if (lalasexoo >= 0xFFFF8000)
    {
        if (lalasexoo > 0x8000)
            lalasex -= 0x10000;
    }
    else
    {
        lalasexoo += 0x10000;
    }

    *(uintptr_t*)(&pubkey) = lalasex;

    int res = 0;

    if (format & 2)
    {
        res = crypto_aead_aes256gcm_decrypt_detached(
            packet,
            0,
            packet,
            len - 18,
            &packet[len - 16],
            0,
            0,
            pubkey,
            client_tx_key
        );

        if (res != 0)
        {
            g_print("Decryption failed! (res = %d)\n", res);
        }
    }
    else
    {
        res = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            packet,
            0,
            packet,
            len - 18,
            &packet[len - 16],
            0,
            0,
            pubkey,
            client_tx_key
        );

        if (res != 0)
        {
            g_print("Decryption failed! (res = %d)\n", res);
        }
    }

    int v13 = recvNonce - (client_txnonce & 0xFFFFuLL);
    if (v13 >= (int)0xFFFF8000)
    {
        if (v13 > 0)
        {
            client_txnonce &= 0xFFFFFFFFFFFF0000uLL;
            client_txnonce |= recvNonce;
        }
    }
    else
    {
        client_txnonce = recvNonce | (client_txnonce + 0x10000) & 0xFFFFFFFFFFFF0000uLL;
    }

    return res;
}

static int
decrypt_roblox_packet_ingoing(unsigned char* packet, int len, char format)
{
    // yes yes nasec writes goooooooood cleaaaaannn codeeeee
    unsigned char* header = &packet[len - 18];
    unsigned char pubkey[12];
    memcpy(pubkey, "UniqueNumbeR", 12);

    UINT16 recvNonce = *(UINT16*)header;

    uintptr_t lalasex = recvNonce | client_rxnonce & 0xFFFFFFFFFFFF0000uLL;

    uintptr_t lalasexoo = recvNonce - (client_rxnonce & 0xFFFFuLL);

    if (lalasexoo >= 0xFFFF8000)
    {
        if (lalasexoo > 0x8000)
            lalasex -= 0x10000;
    }
    else
    {
        lalasexoo += 0x10000;
    }

    *(uintptr_t*)(&pubkey) = lalasex;

    int res = 0;

    if (format & 2)
    {
        res = crypto_aead_aes256gcm_decrypt_detached(
            packet,
            0,
            packet,
            len - 18,
            &packet[len - 16],
            0,
            0,
            pubkey,
            client_rx_key
        );

        if (res != 0)
        {
            g_print("Decryption failed! (res = %d)\n", res);
        }
    }
    else
    {
        res = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            packet,
            0,
            packet,
            len - 18,
            &packet[len - 16],
            0,
            0,
            pubkey,
            client_rx_key
        );

        if (res != 0)
        {
            g_print("Decryption failed! (res = %d)\n", res);
        }
    }

    int v13 = recvNonce - (client_rxnonce & 0xFFFFuLL);
    if (v13 >= (int)0xFFFF8000)
    {
        if (v13 > 0)
        {
            client_rxnonce &= 0xFFFFFFFFFFFF0000uLL;
            client_rxnonce |= recvNonce;
        }
    }
    else
    {
        client_rxnonce = recvNonce | (client_rxnonce + 0x10000) & 0xFFFFFFFFFFFF0000uLL;
    }

    return res;
}

void test_decryption()
{
    //create_roblox_bridge();

    // 0x43
    //unsigned char packet[] = { 0x81, 0xC7, 0x05, 0x00, 0x60, 0x00, 0xC8, 0x7F, 0x05, 0x00, 0xEE, 0x03, 0x00, 0x00, 0x83, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xD6, 0x73, 0x00, 0x05, 0xD6, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC8, 0x83, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xD6, 0x73, 0x00, 0x05, 0xD6, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xE7, 0x78, 0x69, 0x71, 0x75, 0x65, 0x4E, 0x75, 0x6D, 0x62, 0x65, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    unsigned char packet[] = { 0x71, 0x57, 0x22, 0x70, 0xDC, 0x1B, 0x55, 0x97, 0x4B, 0x2E, 0x80, 0x84, 0xEA, 0x0D, 0xAF, 0x0C, 0xE3, 0xA1, 0x22, 0x70, 0x84, 0x33, 0x4A, 0x63, 0x48, 0xBF, 0x40, 0x1F, 0x34, 0xB3, 0x86, 0x22, 0xB0, 0x85, 0x2A, 0xBB, 0x2A, 0xB1, 0x61, 0xB3, 0x06, 0x41, 0xC7, 0x51, 0xDB, 0x4D, 0x0C, 0x3F, 0xA4, 0xA6, 0x75, 0x36, 0x52, 0x1C, 0xBC, 0x92, 0xE6, 0x77, 0xCB, 0x13, 0xF4, 0x4A, 0x88, 0x7C, 0xF2, 0xC7, 0x21, 0x08, 0x70, 0xFB, 0x70, 0x66, 0xC9, 0x1B, 0x7C, 0x78, 0x3E, 0xC0, 0x78, 0x21, 0xE8, 0xB2, 0x79, 0x36, 0xDE };

    _U_;
    decrypt_roblox_packet(packet, sizeof(packet), 2);

    /*
    char* buffer = "\x22";
    char* k = "\x22";

    crypto_aead_chacha20poly1305_ietf_decrypt_detached(buffer, 0, buffer, sizeof(buffer) - 18, &buffer[sizeof(buffer) - 16],0,0,4,k);
    */
}

void
retrieve_decryption_keys(unsigned char* client_rx,unsigned char* client_tx)
{
    rbx_getdecryptionkeys(roblox_process, rakpeer_crypto, client_rx, client_tx);
}

typedef struct {
    gboolean decrypted_ok;
    gboolean processed;
    guint64  nonce_used;
    tvbuff* decrypted_data;
} ronet_frame_t;


int connectionPhase = 0; // 0 = offline, 1 = handshake, 2 = connected

extern "C"
static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "nigga");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);


    bool isSend = pinfo->srcport == sourcePort;

    ronet_frame_t* fdata = (ronet_frame_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_foo, 0);

    if (!fdata) {
        fdata = wmem_new0(wmem_file_scope(), ronet_frame_t);

        p_add_proto_data(wmem_file_scope(), pinfo, proto_foo, 0, fdata);
    }

    auto Stream = new NetworkStream((unsigned char*)tvb_get_ptr(tvb, 0, tvb_reported_length(tvb)), tvb_reported_length(tvb),true);

    if (ruppMode)
    {
        deserialize_rupp_header(Stream);
    }

    if (!fdata->processed)
    {
        if (test_offline_message(tvb, pinfo, tree, data))
        {
            // Offline message

            // Either ID_OPEN_CONNECTION_REQUEST_1 or ID_OPEN_CONNECTION_REQUEST_2

            UINT8 RequestId = Stream->Read<UINT8>();

            if (RequestId == 0x7B && connectionPhase == 0)
            {
                // ID_OPEN_CONNECTION_REQUEST_1
                Stream->IgnoreBytes(sizeof(RAKNET_OFFLINE_MESSAGE_DATA_ID)); // Skip OFFLINE_MESSAGE_ID
                UINT8 ProtocolVersion = Stream->Read<UINT8>(); // Protocol version

                g_print("Protocol Version: %u\n", ProtocolVersion);

                // Actually always should be 5
                connectionPhase = 1;

                sourcePort = pinfo->srcport;
            }
            else if (RequestId == 0x78 && connectionPhase == 1)
            {
                // ID_OPEN_CONNECTION_REQUEST_2
                Stream->IgnoreBytes(sizeof(RAKNET_OFFLINE_MESSAGE_DATA_ID)); // Skip OFFLINE_MESSAGE_ID
                Stream->Read<UINT8>(); // Seems like some deprecated unused field to indicate the operation

                UINT8 aadSize = Stream->Read<UINT8>(); _U_
                USHORT encryptedDataSize = Stream->Read<USHORT>(true); _U_
                USHORT keyVersion = Stream->Read<USHORT>(true); _U_
                unsigned char* pubKey = Stream->ReadBytes(0x20); _U_

                UINT8 macStringFirstChar = Stream->Read<UINT8>(); _U_ // used to 0 string terminate ig
                UINT8 macStringLen = Stream->Read<UINT8>(); _U_

                unsigned char* macStr = Stream->ReadBytes(macStringLen); _U_
                // Now comes the AuthBlob that is encrypted and sadly we are not able to decrypt it yet :(
                // The reason is that roblox does wipe the secret key and public key after reveing the server response
                // we are sniffing packets, we are out of sync of roblox, race conditions can and WILL happen
                // In short, we can't get the keys in time before roblox wipes them

                // BUT We are 100% sure that this port is our raknet

                g_print("dummer fetus %u\n", pinfo->srcport);

                create_roblox_bridge();

                retrieve_decryption_keys(client_tx_key, client_rx_key);

                connectionPhase = 2;
            }
            else
            {
                // Unknown offline message
                g_print("Unknown offline message %x\n", RequestId);
            }
        }
        else if (connectionPhase == 2)
        {
            if (!rakpeer_crypto)
            {
                create_roblox_bridge();
                retrieve_decryption_keys(client_tx_key, client_rx_key);

                if (client_tx_key[0] == 0 && client_tx_key[1] == 0)
                {
                    g_print("Failed to retrieve decryption keys\n");
                    return tvb_captured_length(tvb);
                }
            }

            // Connected and expect encrypted packet

            if (!pinfo->fd->visited)
            {
                //g_print("decrypting %u %u\n", pinfo->srcport, tvb_reported_length(tvb));

                int res = 0;

                if (isSend)
                {
                    if (ruppMode)
                    {
                        res = decrypt_roblox_packet(Stream->data + Stream->readOffset, Stream->numberOfBytesUsed - Stream->readOffset, rbx_getcryptoformat(roblox_process, rakpeer_crypto));
                    }
                    else
                    {
                        res = decrypt_roblox_packet(Stream->data, Stream->numberOfBytesUsed, rbx_getcryptoformat(roblox_process, rakpeer_crypto));
                    }
                }
                else
                {
                    if (ruppMode)
                    {
                        res = decrypt_roblox_packet_ingoing(Stream->data + Stream->readOffset, Stream->numberOfBytesUsed - Stream->readOffset, rbx_getcryptoformat(roblox_process, rakpeer_crypto));
                    }
                    else
                    {
                        res = decrypt_roblox_packet_ingoing(Stream->data, Stream->numberOfBytesUsed, rbx_getcryptoformat(roblox_process, rakpeer_crypto));
                    }
                }


                guint8* decrypted_data = (guint8*)wmem_alloc(wmem_file_scope(), ruppMode ? Stream->numberOfBytesUsed : Stream->numberOfBytesUsed - Stream->readOffset);

                if (ruppMode)
                {
                    memcpy(decrypted_data, Stream->data + Stream->readOffset, Stream->numberOfBytesUsed - Stream->readOffset);
                }
                else
                {
                    memcpy(decrypted_data, Stream->data, Stream->numberOfBytesUsed);
                }

                tvbuff* decrypted_tvb = tvb_new_real_data(decrypted_data, Stream->numberOfBytesUsed, tvb_reported_length(tvb));

                fdata->decrypted_data = decrypted_tvb;
                fdata->decrypted_ok = res != -1; // TODO: add decryption check

                //sourcePort = 0;
            }
        }

        fdata->processed = true;
    }


    if (fdata->processed) // Connected
    {
        // We now have access to the payload

        if (fdata->decrypted_ok)
        {
            proto_item* ti = proto_tree_add_item(tree, proto_foo, fdata->decrypted_data, 0, -1, ENC_NA);
            proto_tree* ronet_tree = proto_item_add_subtree(ti, ett_ronet);

            col_set_str(pinfo->cinfo, COL_PROTOCOL, isSend ? "niggaclient" : "niggaserver");

            BitStream bitStream((unsigned char*)tvb_get_ptr(fdata->decrypted_data, 0, tvb_reported_length(fdata->decrypted_data)), tvb_reported_length(fdata->decrypted_data));
            add_new_data_source(pinfo, fdata->decrypted_data,"Decrypted");

            proto_tree_add_item(ronet_tree, hf_ronet_decrypted_payload, fdata->decrypted_data, 0, -1, ENC_NA);

            // multiple raknet packets can reside in a single udp packet
            
            {
                proto_tree* datagram_tree = proto_tree_add_subtree(ronet_tree, fdata->decrypted_data, 0, -1, ett_ronet_datagram, NULL, "RakNet Datagram");

                DatagramHeaderFormat dheader;
                ZeroMemory(&dheader, sizeof(DatagramHeaderFormat));

                DeserializeDatagramHeader(&bitStream, &dheader);

                proto_tree_add_boolean(datagram_tree, hf_ronet_isValid, fdata->decrypted_data, 0, 1, dheader.isValid);
                proto_tree_add_boolean(datagram_tree, hf_ronet_isAck, fdata->decrypted_data, 0, 1, dheader.isACK);
                proto_tree_add_boolean(datagram_tree, hf_ronet_isIngoing, fdata->decrypted_data, 0, 1, !isSend);
                proto_tree_add_boolean(datagram_tree, hf_ronet_isNack, fdata->decrypted_data, 0, 1, dheader.isNAK);
                proto_tree_add_boolean(datagram_tree, hf_ronet_isJoindata, fdata->decrypted_data, 0, 1, dheader.isJoinData);
                proto_tree_add_uint(datagram_tree, hf_ronet_datagramNumber, fdata->decrypted_data, 1, 3, dheader.datagramNumber);

                if (dheader.isValid && !dheader.isACK && !dheader.isNAK)
                {
                    bitStream.AlignReadToByteBoundary();

                    while (bitStream.readOffset < bitStream.numberOfBitsUsed)
                    {
                        RakNet_PacketReliability reliability;
                        reliability = UNRELIABLE;
                        bitStream.ReadBits((unsigned char*)&reliability, 3, true);

                        if (reliability >= NUMBER_OF_RELIABILITIES)
                        {
                            printf("invalid reliability %u %p %x\n", reliability, (void*)&dheader, bitStream.data[0]);
                            MessageBoxA(0, "Invalid reliability", "Error", MB_OK | MB_ICONERROR);

                            delete Stream;
                            return tvb_captured_length(tvb);
                        }

                        bool hasSplitPacket = false;
                        bitStream.Read(hasSplitPacket);

                        bitStream.AlignReadToByteBoundary();

                        uint16_t dataBitLength;
                        bitStream.ReadShort(dataBitLength);

                        uint32_t reliableMessageNumber = -1;
                        if (reliability == RELIABLE ||
                            reliability == RELIABLE_SEQUENCED ||
                            reliability == RELIABLE_ORDERED)
                        {
                            bitStream.ReadUint24(reliableMessageNumber);
                        }

                        bitStream.AlignReadToByteBoundary();


                        uint32_t sequencingIndex;

                        if (reliability == UNRELIABLE_SEQUENCED ||
                            reliability == RELIABLE_SEQUENCED)
                        {
                            bitStream.ReadUint24(sequencingIndex);
                        }

                        uint32_t orderingIndex = 0;
                        uint8_t orderingChannel = 0;

                        if (reliability == UNRELIABLE_SEQUENCED ||
                            reliability == RELIABLE_SEQUENCED ||
                            reliability == RELIABLE_ORDERED ||
                            reliability == RELIABLE_ORDERED_WITH_ACK_RECEIPT)
                        {
                            bitStream.ReadUint24(orderingIndex);
                            bitStream.ReadBits(&orderingChannel, 8, false);
                        }

                        uint32_t splitPacketCount = 0;
                        uint32_t splitPacketIndex = 0;
                        uint16_t splitPacketId = 0;

                        if (hasSplitPacket)
                        {
                            bitStream.ReadUint32(splitPacketCount);
                            bitStream.ReadUint16(splitPacketId);
                            bitStream.ReadUint32(splitPacketIndex);
                        }

                        uint32_t payloadSize = BITS_TO_BYTES(dataBitLength);

                        if (payloadSize < 1 || payloadSize > 0x1000)
                        {
                            printf("invalid payload size %u\n", payloadSize);

                            delete Stream;
                            return tvb_captured_length(tvb);
                        }

                        proto_tree* internalPacket_tree = proto_tree_add_subtree(ronet_tree, fdata->decrypted_data, 0, -1, ett_ronet_internalPacket, NULL, "Internal Packet");

                        proto_tree_add_boolean(internalPacket_tree, hf_ronet_isSplitPacket, fdata->decrypted_data, 4, 5, hasSplitPacket);
                        //proto_tree_add_uint(internalPacket_tree, hf_ronet_reliability, fdata->decrypted_data, 4, 5, reliability);


                        guint8* payload = (guint8*)wmem_alloc(wmem_file_scope(), payloadSize);
                        bitStream.ReadBits(payload, BYTES_TO_BITS(payloadSize), false);

                        tvbuff* parsed_tvb = tvb_new_real_data(payload, payloadSize, tvb_reported_length(fdata->decrypted_data));
                        char wow[32];
                        itoa(dheader.datagramNumber, wow, 10);
                        add_new_data_source(pinfo, parsed_tvb, (std::string("User Payload ") + wow).c_str());

                        col_set_str(pinfo->cinfo, COL_PROTOCOL, isSend ? "niggawario" : "niggaluigi");

                        proto_tree_add_item(internalPacket_tree, hf_ronet_user_payload, parsed_tvb, 0, -1, ENC_NA);

                        // Roblox Specific packet Deserialzation

                        proto_tree* roblox_tree = proto_tree_add_subtree(ronet_tree, fdata->decrypted_data, 0, -1, ett_ronet_roblox, NULL, "Roblox");


                        printf("Payload Size: %u\n", payloadSize);


                        NetworkStream userPayloadStream(payload, payloadSize, false);

                       	//STRIPPED c:
                    }

                }
            }
        }
        else
        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "nigger.");
        }
    }

    delete Stream;

    return tvb_captured_length(tvb);
}


extern "C"
void
proto_register_foo(void)
{
    static hf_register_info hf[] = {
    {
       &hf_ronet_datagramNumber,
        { "Datagram Number", "ronet.datagram",
        FT_UINT24, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL },

    },
    {
       &hf_ronet_isValid,
        { "isValid", "ronet.isValid",
        FT_BOOLEAN, NULL,
        NULL, 0x0,
        NULL, HFILL },
    },
    {
       &hf_ronet_isAck,
        { "Ack", "ronet.isAck",
        FT_BOOLEAN, NULL,
        NULL, 0x0,
        NULL, HFILL },
    },
    {
       &hf_ronet_isIngoing,
        { "Ingoing", "ronet.isIngoing",
        FT_BOOLEAN, NULL,
        NULL, 0x0,
        NULL, HFILL },
    },
    {
       &hf_ronet_isNack,
        { "Nack", "ronet.isNack",
        FT_BOOLEAN, NULL,
        NULL, 0x0,
        NULL, HFILL },
    },
    {
       &hf_ronet_isJoindata,
        { "isJoinData", "ronet.isJoinData",
        FT_BOOLEAN, NULL,
        NULL, 0x0,
        NULL, HFILL },
    },
    {
       &hf_ronet_isSplitPacket,
        { "isSplitPacket", "ronet.isSplitPacket",
        FT_BOOLEAN, NULL,
        NULL, 0x0,
        NULL, HFILL },
    },
    {
       &hf_ronet_isPingItem,
        { "isPingItem", "ronet.isPingItem",
        FT_BOOLEAN, NULL,
        NULL, 0x0,
        NULL, HFILL },
    },
    {
       &hf_ronet_user_payload,
        { "User Payload", "ronet.user_payload",
        FT_BYTES, SEP_SPACE,
        NULL, 0x0,
        NULL, HFILL },
    },
    {
       &hf_ronet_decrypted_payload,
        { "Decrypted Payload", "ronet.decrypted_payload",
        FT_BYTES, SEP_SPACE,
        NULL, 0x0,
        NULL, HFILL },
    }
    };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_ronet,
        &ett_ronet_datagram,
        &ett_ronet_internalPacket,
        &ett_ronet_roblox,
    };

    proto_foo = proto_register_protocol (
        "fetus Protocol", /* protocol name        */
        "fetus",          /* protocol short name  */
        "ronet"           /* protocol filter_name */
        );

    proto_register_field_array(proto_foo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    foo_handle = register_dissector_with_description (
        "fetus",          /* dissector name           */
        "fetus Protocol", /* dissector description    */
        dissect_foo,    /* dissector function       */
        proto_foo       /* protocol being dissected */
        );


    module_t* wimax_module;
    wimax_module = prefs_register_protocol(proto_foo, NULL);


    prefs_register_bool_preference(wimax_module, "blackie", "nigger", "faggot", &niggamode);

    AllocConsole();
    freopen("CONOUT$", "w", stdout);


    /*
    attached_process* proc = mem_attachx("RobloxPlayerBeta.exe");
    rbx_getdatamodel(proc);
    */
    //retrieve_decryption_keys(0,0,false);
}


extern "C"
void
proto_reg_handoff_foo(void)
{
    //dissector_add_uint("udp.port", FOO_PORT, foo_handle);
    //dissector_add_uint("udp.srcport", 62428, foo_handle);

    heur_dissector_add("udp", dissect_ronet_heur,
        "Roblox Raknet over UDP", "ronet_udp", proto_foo, HEURISTIC_ENABLE);
}
