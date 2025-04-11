#include <chrono>
#include <iostream>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include "cpr/cpr.h"
#include "BlockHeader.h"
#include "CoinbaseTransaction.h"
#include "Block.h"
#include "NetworkMessageTypes.h"
#include "cpu_sha256.h"

// External CUDA definitions
extern "C" void hash_init(uint32_t* sha256_state, uint32_t target);
extern "C" bool hash_iteration(BlockHeader* block_header);
extern "C" void hash_cleanup();

void printHex(const void* data, size_t size = 80) {
	// Debug function to print bytes as hex
	const unsigned char* bytes = static_cast<const unsigned char*>(data);
	for (size_t i = 0; i < size; i++) {
		printf("%02x", bytes[i]);
	}
	printf("\n");
}

int main() {
	// Variables
	CPU_SHA256_CTX cpu_sha256_ctx;
	uint8_t tmp_out_hash[32];

	// Set float print precision and print info
	std::cout << std::setprecision(3);
	std::cout << "Starting" << std::endl;

	// Start WSA
	WSAData wsaData;
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) return 1;

	// Create a socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		std::cout << "Could not create socket!" << std::endl;
		WSACleanup();
		return 1;
	}

	// Set the sockets connection data
	SOCKADDR_IN addr;
	addr.sin_family = AF_INET;
	// Change IP here if you want to connect to a node that isn't your own
	// Note: it only sets the data here, it conects only once a block is mined
	inet_pton(AF_INET, "127.0.0.1", &(addr.sin_addr)); // IP
	addr.sin_port = htons(8333); // Port

	// Print info
	std::cout << "Getting blockchain data" << std::endl;

	// Get data from public HTTPS API (blockchain.com)
	// Using a public API has downsides but was simple to implement
	// Ideally you would connect to a node here instead
	// Please respect the rules on blockchain.com and don't send requests too often
	// TODO: get n_bits too
	cpr::Response last_hash_response = cpr::Get(cpr::Url{"https://blockchain.info/q/latesthash"});
	cpr::Response block_count_response = cpr::Get(cpr::Url{"https://blockchain.info/q/getblockcount"});
	if (last_hash_response.status_code != 200 || block_count_response.status_code != 200) {
		std::cout << "Could not get blockchain data!" << std::endl;
		WSACleanup();
		return 1;
	}
	uint32_t n_bits = 0x17025105; // This value will change sometimes when the bitcoin target changes, make sure it's up to date!
	uint32_t block_height = std::stoul(block_count_response.text);
	uint8_t* block_height_bytes = reinterpret_cast<uint8_t*>(&block_height);

	// Print info
	std::cout << "Creating data structures" << std::endl;

	// Construct the coinbase transaction
	CoinbaseTransactionInput coinbase_input;
	coinbase_input.script[1] = *(block_height_bytes+2);
	coinbase_input.script[2] = *(block_height_bytes+1);
	coinbase_input.script[3] = *(block_height_bytes);
	CoinbaseTransactionOutput coinbase_output;
	CoinbaseTransaction coinbase;
	coinbase.input = coinbase_input;
	coinbase.output = coinbase_output;

	// Construct the block header
	BlockHeader block_header;
	for (uint8_t i = 0; i < 32; ++i) {
		std::string byteString = last_hash_response.text.substr(62 - (i * 2), 2);
		block_header.previous_block_hash[i] = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
	}
	cpu_sha256_init(&cpu_sha256_ctx);
	cpu_sha256_update(&cpu_sha256_ctx, reinterpret_cast<uint8_t*>(&coinbase), 176);
	cpu_sha256_final(&cpu_sha256_ctx, block_header.merkle_root);
	cpu_sha256_init(&cpu_sha256_ctx);
	cpu_sha256_update(&cpu_sha256_ctx, block_header.merkle_root, 32);
	cpu_sha256_final(&cpu_sha256_ctx, block_header.merkle_root);
	block_header.n_bits = n_bits;

	// Construct the full block
	Block block;
	block.header = block_header;
	block.coinbase_transaction = coinbase;

	// Initialize CUDA hashing
	cpu_sha256_init(&cpu_sha256_ctx);
	cpu_sha256_transform(cpu_sha256_ctx.state, reinterpret_cast<uint8_t*>(&block_header));
	cpu_sha256_3rounds(cpu_sha256_ctx.state, reinterpret_cast<uint8_t*>(&block_header)+64);
	hash_init(cpu_sha256_ctx.state, (n_bits & 0x00FFFFFF));

	// Print info
	std::cout << "Starting hash loop" << std::endl;

	// Main loop
	auto exact_timer = std::chrono::steady_clock::now();
	uint64_t tried_count = 0;
	while (true) {
		// Update block data
		block_header.current_time = static_cast<uint32_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

		// Hashing
		if (hash_iteration(&block_header)) {
			std::cout << "SUCCESS!" << std::endl;
			printHex(&block_header);
			break;
		}

		// Print info
		auto exact_time = std::chrono::steady_clock::now();
		uint32_t exact_duration = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(exact_time - exact_timer).count());
		float giga_hashes_per_second = (4294967296.0f/exact_duration)/1000000;
		exact_timer = exact_time;
		tried_count += 4294967296u;
		std::cout << giga_hashes_per_second << " GH/s, " << tried_count << " hashes tried" << std::endl;
	}

	// The rest of the code only executes once a valid block is mined which in my case will take on average 11000000 years. Yay!

	// Connect the socket
	if (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) < 0) {
		std::cout << "Could not connect to node!" << std::endl;
		closesocket(sock);
		WSACleanup();
		hash_cleanup();
		return 1;
	}

	// Print info
	std::cout << "Connected to a node" << std::endl;

	// Construct a version message
	VersionMessage version_message;
	version_message.time = static_cast<uint32_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
	cpu_sha256_init(&cpu_sha256_ctx);
	cpu_sha256_update(&cpu_sha256_ctx, reinterpret_cast<uint8_t*>(&version_message) + 24, 85);
	cpu_sha256_final(&cpu_sha256_ctx, tmp_out_hash);
	cpu_sha256_init(&cpu_sha256_ctx);
	cpu_sha256_update(&cpu_sha256_ctx, tmp_out_hash, 32);
	cpu_sha256_final(&cpu_sha256_ctx, tmp_out_hash);
	for (uint8_t i = 0; i < 4; i++) {
		version_message.checksum[i] = tmp_out_hash[i];
	}

	// Construct a verack message
	VerackMessage verack_message;

	// Print info
	std::cout << "Sending version message" << std::endl;

	// Send the version message
	send(sock, reinterpret_cast<const char*>(&version_message), sizeof(VersionMessage), 0);

	// Receive messages
	uint8_t recv_buffer[4096];
	uint32_t recv_buffer_counter = 0;
	while (true) {
		std::cout << "Receiving..." << std::endl;
		int16_t bytesReceived = recv(sock, reinterpret_cast<char*>(recv_buffer) + recv_buffer_counter, 4096 - recv_buffer_counter, 0);
		if (bytesReceived == 0) {
			std::cout << "Disconnected from node!" << std::endl;
			closesocket(sock);
			WSACleanup();
			hash_cleanup();
			return 1;
		}

		// Minimum size
		recv_buffer_counter += bytesReceived;
		if (recv_buffer_counter < 24) continue;

		// 12 command bytes
		std::string r_command;
		for (uint8_t i = 4; i < 16; i++) {
			if (recv_buffer[i] < 33 || recv_buffer[i] > 126) continue;
			r_command += recv_buffer[i];
		}

		// 4 length bytes
		uint32_t r_len = (static_cast<int>(recv_buffer[16])) |
			(static_cast<int>(recv_buffer[17]) << 8) |
			(static_cast<int>(recv_buffer[18]) << 16) |
			(static_cast<int>(recv_buffer[19]) << 24);

		// Checks
		if (r_len > recv_buffer_counter - 24) continue;
		recv_buffer_counter = 0;

		// Commands
		if (r_command == "version") {
			std::cout << "Version command received" << std::endl;
		}
		else if (r_command == "verack") {
			std::cout << "Verack command received" << std::endl;
			break;
		}
		else
		{
			std::cout << "Strange command received: " << r_command << std::endl;
		}
	}

	// Print info
	std::cout << "Sending verack message" << std::endl;

	// Send the verack message
	send(sock, reinterpret_cast<const char*>(&verack_message), sizeof(VerackMessage), 0);

	// Construct a block message
	BlockMessage block_message;
	block_message.block = block;
	cpu_sha256_init(&cpu_sha256_ctx);
	cpu_sha256_update(&cpu_sha256_ctx, reinterpret_cast<uint8_t*>(&block), sizeof(Block));
	cpu_sha256_final(&cpu_sha256_ctx, tmp_out_hash);
	cpu_sha256_init(&cpu_sha256_ctx);
	cpu_sha256_update(&cpu_sha256_ctx, tmp_out_hash, 32);
	cpu_sha256_final(&cpu_sha256_ctx, tmp_out_hash);
	for (uint8_t i = 0; i < 4; i++) {
		block_message.checksum[i] = tmp_out_hash[i];
	}

	// Print info
	std::cout << "Sending block message" << std::endl;

	// Send the block message
	send(sock, reinterpret_cast<const char*>(&block_message), sizeof(BlockMessage), 0);

	// Print info and sleep for 2 seconds
	std::cout << "Sent block data!" << std::endl;
	std::this_thread::sleep_for(std::chrono::seconds(2));
	std::cout << "Stopping" << std::endl;

	// Cleanup and return
	closesocket(sock);
	WSACleanup();
	hash_cleanup();
	return 0;
}
