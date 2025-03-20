#include <cuda_runtime.h>
#include "device_launch_parameters.h"
#include "BlockHeader.h"

// SHA-256 macros
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) ((x & (y | z)) | (y & z))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

// SHA-256 constants
__constant__ uint32_t dev_k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// CUDA device memory pointers
uint32_t* cuda_header_m_in;
uint32_t* cuda_target_in;
uint32_t* cuda_sha256_state_in;
bool* cuda_success_out;
uint32_t* cuda_nonce_out;

__global__ void hash_and_check(const uint32_t* __restrict__ header_m_in,
							   const uint32_t* __restrict__ cuda_target_in,
							   const uint32_t* __restrict__ sha256_state_in,
							   bool* __restrict__ success_out,
							   uint32_t* __restrict__ nonce_out) {
	if (*success_out == true) return;
	uint32_t block_i = (blockIdx.x * blockDim.x + threadIdx.x) << 10;
	uint32_t a, b, c, d, e, f, g, h, t1;
	uint32_t m[58] = { 0 }; // 58 instead of 64 to save registers and computations - initialize all to 0

	// Loop iterations (1024 iterations needs to be the same as above block_i bitshift amount)
#pragma unroll
	for (uint16_t iter = 0; iter < 1024; ++iter) {
		// Set state to the precomputed result of the first chunk + 3 rounds of second chunk
		a = sha256_state_in[0];
		b = sha256_state_in[1];
		c = sha256_state_in[2];
		d = sha256_state_in[3];
		e = sha256_state_in[4];
		f = sha256_state_in[5];
		g = sha256_state_in[6];
		h = sha256_state_in[7];

		// Prepare m for first hashing
		m[0] = header_m_in[0];   // Block header end
		m[1] = header_m_in[1];
		m[2] = header_m_in[2];
		m[3] = (block_i + iter); // Nonce = block_i+iter
		m[4] = 0x80000000;       // Append binary 1
		m[9] = 640;              // Size in bits (of entire block header)
#pragma unroll
		for (uint8_t i = 16; i < 64; ++i) {
			// Since m only has 58 elements, if statements (optimized due to unrolling) make sure generated values are correct
			uint32_t t1 = (i >= 17) ? SIG1(m[i - 8]) : 0;
			uint32_t t2 = (i >= 22) ? m[i - 13] : 0;
			uint32_t t3 = (i >= 30) ? SIG0(m[i - 21]) : ((i <= 19) ? SIG0(m[i - 15]) : 0);
			uint32_t t4 = (i >= 31) ? m[i - 22] : ((i <= 20) ? m[i - 16] : 0);
			m[i - 6] = t1 + t2 + t3 + t4;
		}

		// First hash (finish second chunk, first chunk and first 3 rounds of second chunk are precomputed on CPU)
#pragma unroll
		for (uint8_t i = 3; i < 64; ++i) {
			// Since m only has 58 elements, if statements (optimized due to unrolling) make sure it all works
			if (i <= 4) t1 = h + EP1(e) + CH(e, f, g) + dev_k[i] + m[i];
			else if (i < 15) t1 = h + EP1(e) + CH(e, f, g) + dev_k[i];
			else t1 = h + EP1(e) + CH(e, f, g) + dev_k[i] + m[i - 6];
			h = g;
			g = f;
			f = e;
			e = d + t1;
			t1 += EP0(a) + MAJ(a, b, c);
			d = c;
			c = b;
			b = a;
			a = t1;
		}

		// Prepare m for second hashing
		m[0] = a + sha256_state_in[0];
		m[1] = b + sha256_state_in[1];
		m[2] = c + sha256_state_in[2];
		m[3] = d + sha256_state_in[3];
		m[4] = e + sha256_state_in[4];
		m[5] = f + sha256_state_in[5];
		m[6] = g + sha256_state_in[6];
		m[7] = h + sha256_state_in[7];
		m[8] = 0x80000000;             // Append binary 1
		m[9] = 256;                    // Length in bits
#pragma unroll
		for (uint8_t i = 16; i < 63; ++i) { // (1 round less for performance since its not needed)
			// Since m only has 58 elements, if statements (optimized due to unrolling) make sure generated values are correct
			uint32_t t1 = (i >= 17) ? SIG1(m[i - 8]) : 0;
			uint32_t t2 = (i >= 22) ? m[i - 13] : 0;
			uint32_t t3 = (i >= 30) ? SIG0(m[i - 21]) : ((i <= 23) ? SIG0(m[i - 15]) : 0);
			uint32_t t4 = (i >= 31) ? m[i - 22] : ((i <= 24) ? m[i - 16] : 0);
			m[i - 6] = t1 + t2 + t3 + t4;
		}

		// Reset state to SHA-256 definitions for second hashing
		a = 0x6a09e667;
		b = 0xbb67ae85;
		c = 0x3c6ef372;
		d = 0xa54ff53a;
		e = 0x510e527f;
		f = 0x9b05688c;
		g = 0x1f83d9ab;
		h = 0x5be0cd19;

		// Second hash (1 round less for performance since its not needed)
#pragma unroll
		for (uint8_t i = 0; i < 63; ++i) {
			// Since m only has 58 elements, if statements (optimized due to unrolling) make sure it all works
			if (i <= 8) t1 = h + EP1(e) + CH(e, f, g) + dev_k[i] + m[i];
			else if (i < 15) t1 = h + EP1(e) + CH(e, f, g) + dev_k[i];
			else t1 = h + EP1(e) + CH(e, f, g) + dev_k[i] + m[i - 6];
			h = g;
			g = f;
			f = e;
			e = d + t1;
			// Compare and set success (using early exiting)
			// Values like 0xa41f32e7 may seem random here but these values make sense trust me
			if (i == 60 && e != 0xa41f32e7) break;
			else if (i == 61 && e != 0xe07c2655) break;
			else if (i == 62) {
				e += 0x9b05688c;
				e = ((e >> 24) & 0x000000ff) | ((e >> 8) & 0x0000ff00) | ((e << 8) & 0x00ff0000) | ((e << 24) & 0xff000000);
				if (e < *cuda_target_in) {
					*nonce_out = (block_i + iter);
					*success_out = true;
					break;
				}
			}
			t1 += EP0(a) + MAJ(a, b, c);
			d = c;
			c = b;
			b = a;
			a = t1;
		}
	}
}

extern "C" void hash_init(uint32_t* sha256_state, uint32_t target) {
	// Allocate memory on device and set some initial data
	cudaMalloc(&cuda_header_m_in, 12);
	cudaMalloc(&cuda_target_in, 4);
	cudaMemcpy(cuda_target_in, &target, 4, cudaMemcpyHostToDevice);
	cudaMalloc(&cuda_sha256_state_in, 32);
	cudaMemcpy(cuda_sha256_state_in, sha256_state, 32, cudaMemcpyHostToDevice);
	cudaMalloc(&cuda_success_out, 1);
	cudaMemset(cuda_success_out, 0, sizeof(bool));
	cudaMalloc(&cuda_nonce_out, 4);
	cudaDeviceSynchronize();
}

extern "C" bool hash_iteration(BlockHeader* block_header) {
	// Format the block header data to send to kernal
	uint32_t m_header_in[3];
	m_header_in[0] = *reinterpret_cast<const uint32_t*>(&block_header->merkle_root[28]);
	m_header_in[1] = block_header->current_time;
	m_header_in[2] = block_header->n_bits;
	// Call the hashing kernel
	cudaMemcpy(cuda_header_m_in, m_header_in, 12, cudaMemcpyHostToDevice);
	hash_and_check<<<16384, 256>>>(cuda_header_m_in, cuda_target_in, cuda_sha256_state_in, cuda_success_out, cuda_nonce_out);
	cudaDeviceSynchronize();
	// Get the result and return
	bool success;
	cudaMemcpy(&success, cuda_success_out, 1, cudaMemcpyDeviceToHost);
	if (success) {
		uint32_t tmp_nonce;
		cudaMemcpy(&tmp_nonce, cuda_nonce_out, 4, cudaMemcpyDeviceToHost);
		block_header->nonce = ((tmp_nonce >> 24) & 0x000000ff) |
			((tmp_nonce >> 8) & 0x0000ff00) |
			((tmp_nonce << 8) & 0x00ff0000) |
			((tmp_nonce << 24) & 0xff000000);
		return true;
	}
	return false;
}

extern "C" void hash_cleanup() {
	// Free memory on device
	cudaFree(cuda_header_m_in);
	cudaFree(cuda_target_in);
	cudaFree(cuda_sha256_state_in);
	cudaFree(cuda_success_out);
	cudaFree(cuda_nonce_out);
}