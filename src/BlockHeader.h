#pragma once

#pragma pack(push, 1)
struct BlockHeader {
	int32_t version = 0x20000000;
	uint8_t previous_block_hash[32];
	uint8_t merkle_root[32];
	uint32_t current_time;
	uint32_t n_bits;
	uint32_t nonce;
};
#pragma pack(pop)