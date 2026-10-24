//go:build cgo && linux

package main

/*
#cgo CFLAGS: -I${SRCDIR} -O3 -w
#cgo LDFLAGS: -L/usr/lib64 -L/usr/lib -l:libOpenCL.so.1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CL_TARGET_OPENCL_VERSION 300
#include "CL/cl.h"

static cl_context g_ctx = NULL;
static cl_command_queue g_queue = NULL;
static cl_program g_prog = NULL;
static cl_kernel g_kernel = NULL;
static cl_device_id g_dev = NULL;
static int g_gpu_initialized = 0;
static char g_gpu_device_name[256] = {0};

static const char* get_gpu_device_name() {
    return g_gpu_device_name;
}

static const char *cl_pow_kernel = 
"#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))\n"
"#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))\n"
"#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))\n"
"#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))\n"
"#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))\n"
"#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))\n"
"#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))\n"
"\n"
"__constant uint K[64] = {\n"
"    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,\n"
"    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,\n"
"    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,\n"
"    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,\n"
"    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,\n"
"    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,\n"
"    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,\n"
"    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2\n"
"};\n"
"\n"
"void sha256_block(uint *state, const uchar *block) {\n"
"    uint w[64];\n"
"    for (int i = 0; i < 16; i++) {\n"
"        w[i] = ((uint)block[i*4] << 24) | ((uint)block[i*4 + 1] << 16) | ((uint)block[i*4 + 2] << 8) | ((uint)block[i*4 + 3]);\n"
"    }\n"
"    for (int i = 16; i < 64; i++) {\n"
"        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];\n"
"    }\n"
"    uint a = state[0], b = state[1], c = state[2], d = state[3];\n"
"    uint e = state[4], f = state[5], g = state[6], h = state[7];\n"
"    for (int i = 0; i < 64; i++) {\n"
"        uint t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];\n"
"        uint t2 = EP0(a) + MAJ(a, b, c);\n"
"        h = g; g = f; f = e; e = d + t1;\n"
"        d = c; c = b; b = a; a = t1 + t2;\n"
"    }\n"
"    state[0] += a; state[1] += b; state[2] += c; state[3] += d;\n"
"    state[4] += e; state[5] += f; state[6] += g; state[7] += h;\n"
"}\n"
"\n"
"void sha256_hash(const uchar *data, uint len, uchar *hash) {\n"
"    uint state[8] = {\n"
"        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,\n"
"        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19\n"
"    };\n"
"    uchar block[64];\n"
"    uint i = 0;\n"
"    while (i + 64 <= len) {\n"
"        for (int k = 0; k < 64; k++) block[k] = data[i + k];\n"
"        sha256_block(state, block);\n"
"        i += 64;\n"
"    }\n"
"    uint rem = len - i;\n"
"    for (uint k = 0; k < rem; k++) block[k] = data[i + k];\n"
"    block[rem] = 0x80;\n"
"    if (rem >= 56) {\n"
"        for (uint k = rem + 1; k < 64; k++) block[k] = 0;\n"
"        sha256_block(state, block);\n"
"        for (uint k = 0; k < 56; k++) block[k] = 0;\n"
"    } else {\n"
"        for (uint k = rem + 1; k < 56; k++) block[k] = 0;\n"
"    }\n"
"    ulong bitlen = (ulong)len * 8;\n"
"    for (int k = 0; k < 8; k++) {\n"
"        block[56 + k] = (uchar)((bitlen >> ((7 - k) * 8)) & 0xFF);\n"
"    }\n"
"    sha256_block(state, block);\n"
"    for (int k = 0; k < 8; k++) {\n"
"        hash[k*4]     = (uchar)((state[k] >> 24) & 0xFF);\n"
"        hash[k*4 + 1] = (uchar)((state[k] >> 16) & 0xFF);\n"
"        hash[k*4 + 2] = (uchar)((state[k] >> 8) & 0xFF);\n"
"        hash[k*4 + 3] = (uchar)(state[k] & 0xFF);\n"
"    }\n"
"}\n"
"\n"
"__kernel void winex_pow_search(\n"
"    __constant uchar *prefix,\n"
"    uint prefix_len,\n"
"    __constant uchar *salt_hex,\n"
"    __constant uchar *target_hex,\n"
"    ulong start_nonce,\n"
"    __global volatile uint *out_found,\n"
"    __global volatile ulong *out_nonce,\n"
"    __global uchar *out_hash\n"
") {\n"
"    if (*out_found != 0) return;\n"
"    uint gid = get_global_id(0);\n"
"    ulong nonce = start_nonce + gid;\n"
"\n"
"    uchar buf[384];\n"
"    for (uint i = 0; i < prefix_len; i++) buf[i] = prefix[i];\n"
"    char n_str[32];\n"
"    int n_len = 0;\n"
"    ulong temp = nonce;\n"
"    if (temp == 0) n_str[n_len++] = '0';\n"
"    else {\n"
"        char rev[32];\n"
"        int r_len = 0;\n"
"        while (temp > 0) {\n"
"            rev[r_len++] = '0' + (temp % 10);\n"
"            temp /= 10;\n"
"        }\n"
"        for (int i = 0; i < r_len; i++) n_str[n_len++] = rev[r_len - 1 - i];\n"
"    }\n"
"    for (int i = 0; i < n_len; i++) buf[prefix_len + i] = (uchar)n_str[i];\n"
"    uint tot_len = prefix_len + n_len;\n"
"\n"
"    uchar h1[32];\n"
"    sha256_hash(buf, tot_len, h1);\n"
"\n"
"    uchar combined[128];\n"
"    const char hex_chars[] = \"0123456789abcdef\";\n"
"    for (int i = 0; i < 32; i++) {\n"
"        combined[i * 2]     = hex_chars[(h1[i] >> 4) & 0x0F];\n"
"        combined[i * 2 + 1] = hex_chars[h1[i] & 0x0F];\n"
"    }\n"
"    for (int i = 0; i < 64; i++) combined[64 + i] = salt_hex[i];\n"
"\n"
"    uchar h2[32];\n"
"    sha256_hash(combined, 128, h2);\n"
"\n"
"    uchar h2_hex[65];\n"
"    for (int i = 0; i < 32; i++) {\n"
"        h2_hex[i * 2]     = hex_chars[(h2[i] >> 4) & 0x0F];\n"
"        h2_hex[i * 2 + 1] = hex_chars[h2[i] & 0x0F];\n"
"    }\n"
"    h2_hex[64] = 0;\n"
"\n"
"    int is_valid = 1;\n"
"    for (int i = 0; i < 64; i++) {\n"
"        if (h2_hex[i] < target_hex[i]) { is_valid = 1; break; }\n"
"        if (h2_hex[i] > target_hex[i]) { is_valid = 0; break; }\n"
"    }\n"
"\n"
"    if (is_valid) {\n"
"        if (atomic_cmpxchg(out_found, 0, 1) == 0) {\n"
"            *out_nonce = nonce;\n"
"            for (int i = 0; i < 64; i++) out_hash[i] = h2_hex[i];\n"
"            out_hash[64] = 0;\n"
"        }\n"
"    }\n"
"}\n";

static int init_native_gpu() {
    if (g_gpu_initialized) return 0;
    cl_uint num_plat = 0;
    clGetPlatformIDs(0, NULL, &num_plat);
    if (num_plat == 0) return -1;
    cl_platform_id *plats = malloc(sizeof(cl_platform_id) * num_plat);
    clGetPlatformIDs(num_plat, plats, NULL);

    cl_platform_id nv_plat = plats[0];
    for (cl_uint i = 0; i < num_plat; i++) {
        char name[256];
        clGetPlatformInfo(plats[i], CL_PLATFORM_NAME, sizeof(name), name, NULL);
        if (strstr(name, "NVIDIA") != NULL) {
            nv_plat = plats[i];
            break;
        }
    }
    free(plats);

    cl_int err = clGetDeviceIDs(nv_plat, CL_DEVICE_TYPE_GPU, 1, &g_dev, NULL);
    if (err != CL_SUCCESS) return -2;

    clGetDeviceInfo(g_dev, CL_DEVICE_NAME, sizeof(g_gpu_device_name), g_gpu_device_name, NULL);

    g_ctx = clCreateContext(NULL, 1, &g_dev, NULL, NULL, &err);
    if (err != CL_SUCCESS) return -3;

    g_queue = clCreateCommandQueue(g_ctx, g_dev, 0, &err);
    if (err != CL_SUCCESS) return -4;

    g_prog = clCreateProgramWithSource(g_ctx, 1, &cl_pow_kernel, NULL, &err);
    err = clBuildProgram(g_prog, 1, &g_dev, "-cl-fast-relaxed-math", NULL, NULL);
    if (err != CL_SUCCESS) return -5;

    g_kernel = clCreateKernel(g_prog, "winex_pow_search", &err);
    if (err != CL_SUCCESS) return -6;

    g_gpu_initialized = 1;
    return 0;
}

static int dispatch_native_gpu_batch(const char *prefix, const char *salt_hex, const char *target_hex, 
                                     unsigned long long start_nonce, unsigned int batch_size,
                                     unsigned long long *found_nonce, char *found_hash) {
    if (!g_gpu_initialized && init_native_gpu() != 0) return -1;

    cl_int err;
    uint pfx_len = strlen(prefix);

    cl_mem pfx_buf = clCreateBuffer(g_ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, pfx_len, (void*)prefix, &err);
    cl_mem salt_buf = clCreateBuffer(g_ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 64, (void*)salt_hex, &err);
    cl_mem target_buf = clCreateBuffer(g_ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 64, (void*)target_hex, &err);

    cl_uint zero = 0;
    cl_ulong zero_ul = 0;
    cl_mem found_buf = clCreateBuffer(g_ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof(cl_uint), &zero, &err);
    cl_mem nonce_buf = clCreateBuffer(g_ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof(cl_ulong), &zero_ul, &err);
    cl_mem hash_buf = clCreateBuffer(g_ctx, CL_MEM_READ_WRITE, 65, NULL, &err);

    clSetKernelArg(g_kernel, 0, sizeof(cl_mem), &pfx_buf);
    clSetKernelArg(g_kernel, 1, sizeof(cl_uint), &pfx_len);
    clSetKernelArg(g_kernel, 2, sizeof(cl_mem), &salt_buf);
    clSetKernelArg(g_kernel, 3, sizeof(cl_mem), &target_buf);
    cl_ulong sn = start_nonce;
    clSetKernelArg(g_kernel, 4, sizeof(cl_ulong), &sn);
    clSetKernelArg(g_kernel, 5, sizeof(cl_mem), &found_buf);
    clSetKernelArg(g_kernel, 6, sizeof(cl_mem), &nonce_buf);
    clSetKernelArg(g_kernel, 7, sizeof(cl_mem), &hash_buf);

    size_t g_work = batch_size;
    clEnqueueNDRangeKernel(g_queue, g_kernel, 1, NULL, &g_work, NULL, 0, NULL, NULL);
    clFinish(g_queue);

    cl_uint h_found = 0;
    clEnqueueReadBuffer(g_queue, found_buf, CL_TRUE, 0, sizeof(cl_uint), &h_found, 0, NULL, NULL);

    if (h_found) {
        cl_ulong h_nonce = 0;
        clEnqueueReadBuffer(g_queue, nonce_buf, CL_TRUE, 0, sizeof(cl_ulong), &h_nonce, 0, NULL, NULL);
        clEnqueueReadBuffer(g_queue, hash_buf, CL_TRUE, 0, 65, found_hash, 0, NULL, NULL);
        *found_nonce = h_nonce;
    }

    clReleaseMemObject(pfx_buf);
    clReleaseMemObject(salt_buf);
    clReleaseMemObject(target_buf);
    clReleaseMemObject(found_buf);
    clReleaseMemObject(nonce_buf);
    clReleaseMemObject(hash_buf);

    return h_found ? 1 : 0;
}
*/
import "C"
import (
	"strings"
	"unsafe"
)

func IsNativeGPUAvailable() (bool, string) {
	res := C.init_native_gpu()
	if res == 0 {
		name := C.GoString(C.get_gpu_device_name())
		if strings.TrimSpace(name) != "" {
			return true, name
		}
		return true, "NVIDIA CUDA Hardware Accelerator"
	}
	return false, ""
}

func RunGPUBatch(prefix, saltHex, targetHex string, startNonce uint64, batchSize uint32) (bool, uint64, string) {
	cPrefix := C.CString(prefix)
	cSalt := C.CString(saltHex)
	cTarget := C.CString(targetHex)
	defer C.free(unsafe.Pointer(cPrefix))
	defer C.free(unsafe.Pointer(cSalt))
	defer C.free(unsafe.Pointer(cTarget))

	var foundNonce C.ulonglong
	var foundHash [65]C.char

	res := C.dispatch_native_gpu_batch(
		cPrefix,
		cSalt,
		cTarget,
		C.ulonglong(startNonce),
		C.uint(batchSize),
		&foundNonce,
		&foundHash[0],
	)

	if res == 1 {
		hStr := C.GoString(&foundHash[0])
		return true, uint64(foundNonce), hStr
	}
	return false, 0, ""
}
