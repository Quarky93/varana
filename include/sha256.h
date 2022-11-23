#pragma once
#include <ap_int.h>
#include <hls_task.h>
#include <hls_stream.h>

struct hash_pkt_t {
    ap_uint<256> data;
    ap_uint<32> recycle;
};

void sha256(hls::stream<hash_pkt_t> &in, hls::stream<hash_pkt_t> &out);
