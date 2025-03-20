#pragma once

#pragma pack(push, 1)
struct CoinbaseTransactionInput {
	uint8_t txid[32] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint32_t vout = 0xffffffff;
	uint8_t script_bytes = 21;
	// script[] has a few important bytes such as the current block height which is set in main.cpp but the rest is a custom message.
	// It currently reads "Bitcoin is cool!".
	// Change the message if you want to (begins at script[5]).
	uint8_t script[21] = { 0x03,0x00,0x00,0x00,0x10,0x42,0x69,0x74,0x63,0x6F,0x69,0x6E,0x20,0x69,0x73,0x20,0x63,0x6F,0x6F,0x6C,0x21 };
	uint32_t sequence = 0xffffffff;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct CoinbaseTransactionOutput {
	int64_t value = 312500000;
	uint8_t pk_script_bytes = 25;
	// P2PKH locking script (uses my bitcoin address, so change this if you want to mine with your own)
	uint8_t pk_script[25] = { 0x76,0xa9,0x14,0xeb,0x34,0x4f,0x7d,0x4a,0x1a,0xa7,0x2c,0x19,0xba,0xe8,0x3d,0x77,0x4f,0x86,0xf9,0x7f,0x80,0x48,0x92,0x88,0xac };
};
#pragma pack(pop)

#pragma pack(push, 1)
struct CoinbaseTransaction {
	int32_t version = 1;
	uint8_t input_count = 1;
	CoinbaseTransactionInput input;
	uint8_t output_count = 1;
	CoinbaseTransactionOutput output;
	uint32_t lock_time = 0;
};
#pragma pack(pop)
