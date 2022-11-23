#include "sha256.h"

const char* IN_HASH = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
const char* EXPECTED_HASH = "9c827201b94019b42f85706bc49c59ff84b5604d11caafb90ab94856c4e1dd7a";

int test_sha256() {
    ap_uint<256> in_hash(IN_HASH, 16);
    ap_uint<256> expected_hash(EXPECTED_HASH, 16);
    hls::stream<hash_pkt_t> in_queue;
    hls::stream<hash_pkt_t> out_queue;

    in_queue.write({in_hash, 1});
    std::cout << "Starting the core..." << std::endl;
    sha256(in_queue, out_queue);
    hash_pkt_t result = out_queue.read();
    if (result.data != expected_hash) {
        std::cout << "result.data = " << result.data.to_string(16, true).c_str() << std::endl;
        return 1;
    }
    std::cout << "Success!" << std::endl;
    return 0;
}

int main() {
    int ret;

    ret = test_sha256();
    if (ret) {
        return ret;
    }

    return 0;
}
