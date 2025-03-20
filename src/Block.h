#pragma once
#include "BlockHeader.h"
#include "CoinbaseTransaction.h"

#pragma pack(push, 1)
struct Block {
	BlockHeader header;
	uint8_t transaction_count = 1;
	CoinbaseTransaction coinbase_transaction;
};
#pragma pack(pop)