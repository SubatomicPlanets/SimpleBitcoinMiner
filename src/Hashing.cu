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
uint32_t* cuda_header_w_in;
uint32_t* cuda_target_in;
uint32_t* cuda_sha256_vars_in;
uint32_t* cuda_sha256_state_in;
bool* cuda_success_out;
uint32_t* cuda_nonce_out;

__global__ void hash_and_check(const uint32_t* __restrict__ header_w_in,
							   const uint32_t* __restrict__ cuda_target_in,
							   const uint32_t* __restrict__ sha256_vars_in,
							   const uint32_t* __restrict__ sha256_state_in,
							   bool* __restrict__ success_out,
							   uint32_t* __restrict__ nonce_out) {
	if (*success_out == true) [[unlikely]] { return; }
	uint32_t a, b, c, d, e, f, g, h, t1;
	uint32_t w[16]; // Sliding window
	uint32_t block_i = (blockIdx.x * blockDim.x + threadIdx.x) << 10;

	__shared__ uint32_t s_dev_k[64];
	if (threadIdx.x < 64) s_dev_k[threadIdx.x] = dev_k[threadIdx.x];
	__syncthreads();

	// Loop iterations (1024 iterations needs to be the same as above block_i bitshift amount)
	for (uint16_t iter = 0; iter < 1024; ++iter) {
		// Prepare w for first hashing
		w[0] = header_w_in[0]; // Block header end
		w[1] = header_w_in[1];
		w[2] = header_w_in[2];
		w[3] = block_i + iter; // Nonce
		w[4] = 0x80000000; // Append binary 1
		w[5] = w[6] = w[7] = w[8] = w[9] = w[10] = w[11] = w[12] = w[13] = w[14] = 0;
		w[15] = 640; // Size in bits (of entire block header)

		// Set state to the precomputed result of the first chunk + 3 rounds of second chunk
		a = sha256_vars_in[0];
		b = sha256_vars_in[1];
		c = sha256_vars_in[2];
		d = sha256_vars_in[3];
		e = sha256_vars_in[4];
		f = sha256_vars_in[5];
		g = sha256_vars_in[6];
		h = sha256_vars_in[7];

		// First hash (finish second chunk, first chunk + 3 rounds of second chunk are already precomputed on CPU)
#pragma unroll
		for (uint8_t i = 3; i < 64; ++i) {
			if (i < 5) t1 = h + EP1(e) + CH(e, f, g) + s_dev_k[i] + w[i];
			else if (i < 15) t1 = h + EP1(e) + CH(e, f, g) + s_dev_k[i];
			else if (i == 15) t1 = h + EP1(e) + CH(e, f, g) + s_dev_k[i] + w[i];
			else {
				uint32_t new_w = SIG1(w[14]) + w[9] + SIG0(w[1]) + w[0];
				#pragma unroll
				for (uint8_t j = 0; j < 15; ++j) w[j] = w[j + 1];
				w[15] = new_w;
				t1 = h + EP1(e) + CH(e, f, g) + s_dev_k[i] + new_w;
			}
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

		// Prepare w for second hashing
		w[0] = a + sha256_state_in[0];
		w[1] = b + sha256_state_in[1];
		w[2] = c + sha256_state_in[2];
		w[3] = d + sha256_state_in[3];
		w[4] = e + sha256_state_in[4];
		w[5] = f + sha256_state_in[5];
		w[6] = g + sha256_state_in[6];
		w[7] = h + sha256_state_in[7];
		w[8] = 0x80000000; // Append binary 1
		w[9] = w[10] = w[11] = w[12] = w[13] = w[14] = 0;
		w[15] = 256; // Size in bits

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
			if (i < 9) t1 = h + EP1(e) + CH(e, f, g) + s_dev_k[i] + w[i];
			else if (i < 15) t1 = h + EP1(e) + CH(e, f, g) + s_dev_k[i];
			else if (i == 15) t1 = h + EP1(e) + CH(e, f, g) + s_dev_k[i] + w[i];
			else {
				uint32_t new_w = SIG1(w[14]) + w[9] + SIG0(w[1]) + w[0];
				#pragma unroll
				for (uint8_t j = 0; j < 15; ++j) w[j] = w[j + 1];
				w[15] = new_w;
				t1 = h + EP1(e) + CH(e, f, g) + s_dev_k[i] + new_w;
			}
			h = g;
			g = f;
			f = e;
			e = d + t1;
			// Compare and set success (using early exiting)
			if (i == 60 && e != 0xa41f32e7) break; // 0xa41f32e7 == -0x5be0cd19 (negative initial h)
			else if (i == 61 && e != 0xe07c2655) break; // 0xe07c2655 == -0x1f83d9ab (negative initial g)
			else if (i == 62) {
				e += 0x9b05688c; // Add inital f
				e = ((e >> 24) & 0x000000ff) | ((e >> 8) & 0x0000ff00) | ((e << 8) & 0x00ff0000) | ((e << 24) & 0xff000000);
				if (e < *cuda_target_in) [[unlikely]] {
					*nonce_out = block_i + iter; // Nonce
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

inline uint32_t reverse_bytes(uint32_t value) {
	// Helper function that reverses byte order
	return ((value >> 24) & 0x000000FF) |
		((value >> 8) & 0x0000FF00) |
		((value << 8) & 0x00FF0000) |
		((value << 24) & 0xFF000000);
}

extern "C" void hash_init(uint32_t* sha256_state, uint32_t target) {
	// Allocate memory on device and set some initial data
	cudaMalloc(&cuda_header_w_in, 12);
	cudaMalloc(&cuda_target_in, 4);
	cudaMemcpy(cuda_target_in, &target, 4, cudaMemcpyHostToDevice);
	cudaMalloc(&cuda_sha256_vars_in, 32);
	cudaMalloc(&cuda_sha256_state_in, 32);
	cudaMemcpy(cuda_sha256_state_in, sha256_state, 32, cudaMemcpyHostToDevice);
	cudaMalloc(&cuda_success_out, 1);
	cudaMemset(cuda_success_out, 0, sizeof(bool));
	cudaMalloc(&cuda_nonce_out, 4);
	cudaDeviceSynchronize();
}

extern "C" bool hash_iteration(BlockHeader* block_header, uint32_t* sha256_vars) {
	// Format the block header data to send to kernal
	uint32_t m_header_in[3];
	m_header_in[0] = reverse_bytes(*reinterpret_cast<const uint32_t*>(&block_header->merkle_root[28]));
	m_header_in[1] = reverse_bytes(block_header->current_time);
	m_header_in[2] = reverse_bytes(block_header->n_bits);

	// Call the hashing kernel
	cudaMemcpy(cuda_header_w_in, m_header_in, 12, cudaMemcpyHostToDevice);
	cudaMemcpy(cuda_sha256_vars_in, sha256_vars, 32, cudaMemcpyHostToDevice);
	hash_and_check<<<16384, 256>>>(cuda_header_w_in, cuda_target_in, cuda_sha256_vars_in, cuda_sha256_state_in, cuda_success_out, cuda_nonce_out);
	cudaDeviceSynchronize();

	// Get the result and return
	bool success;
	cudaMemcpy(&success, cuda_success_out, 1, cudaMemcpyDeviceToHost);
	if (success) {
		uint32_t nonce;
		cudaMemcpy(&nonce, cuda_nonce_out, 4, cudaMemcpyDeviceToHost);
		block_header->nonce = reverse_bytes(nonce);
		return true;
	}
	return false;
}

extern "C" void hash_cleanup() {
	// Free memory on device
	cudaFree(cuda_header_w_in);
	cudaFree(cuda_target_in);
	cudaFree(cuda_sha256_vars_in);
	cudaFree(cuda_sha256_state_in);
	cudaFree(cuda_success_out);
	cudaFree(cuda_nonce_out);
}
