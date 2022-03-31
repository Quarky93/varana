#include "poh.h"

void poh(const ap_uint<256> *in_hashes, // input hashes
         const ap_uint<64> *num_iters,  // input numbers of iterations for each input hash
         unsigned num_hashes,           // input number of hashes (the number of elements in in_hashes and in num_iters)
         ap_uint<256> *out_hashes       // output hashes
) {
#pragma HLS interface m_axi port=in_hashes bundle=gmem
#pragma HLS interface m_axi port=num_iters bundle=gmem
#pragma HLS interface m_axi port=out_hashes bundle=gmem
#pragma HLS interface s_axilite port=in_hashes bundle=control
#pragma HLS interface s_axilite port=num_iters bundle=control
#pragma HLS interface s_axilite port=out_hashes bundle=control
#pragma HLS interface s_axilite port=num_hashes bundle=control
#pragma HLS interface s_axilite port=return bundle=control

    ap_uint<256> in_hashes_batch[BATCH_NUM_HASHES];
    ap_uint<64> num_iters_batch[BATCH_NUM_HASHES];
    ap_uint<256> out_hashes_batch[BATCH_NUM_HASHES];

    for (unsigned i = 0; i < num_hashes; i += BATCH_NUM_HASHES) {
        for (unsigned j = 0; j < BATCH_NUM_HASHES; j++) {
            in_hashes_batch[j] = in_hashes[i * BATCH_NUM_HASHES + j];
        }
        for (unsigned j = 0; j < BATCH_NUM_HASHES; j++) {
            num_iters_batch[j] = num_iters[i + j];
        }

        for (unsigned j = 0; j < BATCH_NUM_HASHES; j++) {
#pragma HLS unroll
            ap_uint<256> out_hash = in_hashes_batch[j];
            ap_uint<64> num_iters_j = num_iters_batch[j];
            for (unsigned k = 0; k < num_iters_j; k++) {
                out_hash = sha256(out_hash);
            }
            out_hashes_batch[j] = out_hash;
        }

        for (unsigned j = 0; j < BATCH_NUM_HASHES; j++) {
            out_hashes[i + j] = out_hashes_batch[j];
#ifndef __SYNTHESIS__
            std::cout << "out_hashes[" << i + j << "] = "
                      << out_hashes[i + j].to_string(16, true).c_str() << std::endl;
#endif
        }
    }
}
