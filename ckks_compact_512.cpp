//==================================================================================
// CKKS Compact 512-byte Encryption
//
// This example tries to find the smallest ring dimension that can encrypt
// 512 bytes while maintaining 128-bit security.
//==================================================================================

#include "openfhe.h"

// Serialization headers
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include <iostream>
#include <sstream>

using namespace lbcrypto;

// Helper function to get serialized size of an object
template<typename T>
size_t getSerializedSize(const T& obj) {
    std::ostringstream os;
    Serial::Serialize(obj, os, SerType::BINARY);
    return os.str().size();
}

void testConfiguration(size_t targetSlots, size_t bytesPerSlot, uint32_t ringDimension,
                      SecurityLevel secLevel, const std::string& secLevelName) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Testing Configuration:" << std::endl;
    std::cout << "  Target: 512 bytes" << std::endl;
    std::cout << "  Bytes per slot: " << bytesPerSlot << std::endl;
    std::cout << "  Required slots: " << targetSlots << std::endl;
    std::cout << "  Ring dimension: " << ringDimension << std::endl;
    std::cout << "  Security level: " << secLevelName << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        // Setup CryptoContext
        CCParams<CryptoContextCKKSRNS> parameters;

        // Set the ring dimension explicitly
        parameters.SetRingDim(ringDimension);

        // Set batch size to our target
        parameters.SetBatchSize(targetSlots);

        // Minimal depth for just encryption
        parameters.SetMultiplicativeDepth(1);

        // Scaling factor - needs to accommodate bytesPerSlot
        // For bytesPerSlot bytes, we need at least 8*bytesPerSlot bits of precision
        uint32_t requiredBits = 8 * bytesPerSlot + 10; // +10 for safety margin
        parameters.SetScalingModSize(std::min(requiredBits, uint32_t(59))); // Max is 59

        // Set requested security level
        parameters.SetSecurityLevel(secLevel);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // Enable features
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        // Get actual parameters
        size_t actualBatchSize = cc->GetEncodingParams()->GetBatchSize();
        size_t actualRingDim = cc->GetRingDimension();

        std::cout << "\nActual parameters after generation:" << std::endl;
        std::cout << "  Ring Dimension: " << actualRingDim << std::endl;
        std::cout << "  Batch Size: " << actualBatchSize << std::endl;

        if (actualBatchSize < targetSlots) {
            std::cout << "ERROR: Batch size too small! Need " << targetSlots
                      << " but got " << actualBatchSize << std::endl;
            return;
        }

        // Generate keys
        std::cout << "\nGenerating keys..." << std::endl;
        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);

        // Create test data
        double maxValue = std::pow(2.0, 8.0 * bytesPerSlot) - 1.0;
        std::vector<double> data(targetSlots);
        for (size_t i = 0; i < targetSlots; i++) {
            // Create test values that use the full range
            data[i] = static_cast<double>((i * 257) % static_cast<size_t>(maxValue + 1));
        }

        // Encrypt
        std::cout << "Encrypting..." << std::endl;
        Plaintext plaintext = cc->MakeCKKSPackedPlaintext(data);
        auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);

        // Measure sizes
        size_t ctSize = getSerializedSize(ciphertext);
        size_t pkSize = getSerializedSize(keyPair.publicKey);
        size_t skSize = getSerializedSize(keyPair.secretKey);

        auto evalMultKeys = cc->GetEvalMultKeyVector(keyPair.secretKey->GetKeyTag());
        size_t relinKeySize = 0;
        for (const auto& key : evalMultKeys) {
            relinKeySize += getSerializedSize(key);
        }

        // Verify decryption
        Plaintext result;
        cc->Decrypt(keyPair.secretKey, ciphertext, &result);
        result->SetLength(targetSlots);
        auto decrypted = result->GetRealPackedValue();

        double maxError = 0.0;
        for (size_t i = 0; i < std::min(targetSlots, size_t(10)); i++) {
            double error = std::abs(data[i] - decrypted[i]);
            maxError = std::max(maxError, error);
        }

        std::cout << "\nResults:" << std::endl;
        std::cout << "========" << std::endl;
        std::cout << "Plaintext size: 512 bytes" << std::endl;
        std::cout << "Ciphertext size: " << ctSize << " bytes (" << ctSize / 1024.0 << " KB)" << std::endl;
        std::cout << "Public key size: " << pkSize << " bytes (" << pkSize / 1024.0 << " KB)" << std::endl;
        std::cout << "Private key size: " << skSize << " bytes (" << skSize / 1024.0 << " KB)" << std::endl;
        std::cout << "Relinearization keys: " << relinKeySize << " bytes (" << relinKeySize / 1024.0 << " KB)" << std::endl;

        size_t totalSize = ctSize + pkSize + skSize + relinKeySize;
        std::cout << "\nTotal size: " << totalSize << " bytes (" << totalSize / 1024.0 << " KB)" << std::endl;
        std::cout << "Ciphertext expansion: " << ctSize / 512.0 << "x" << std::endl;
        std::cout << "Total expansion: " << totalSize / 512.0 << "x" << std::endl;
        std::cout << "Max decryption error: " << maxError << std::endl;

        if (maxError < 0.5) {
            std::cout << "Status: SUCCESS - Values recoverable" << std::endl;
        } else {
            std::cout << "Status: FAIL - Errors too large" << std::endl;
        }

    } catch (const std::exception& e) {
        std::cout << "\nERROR: " << e.what() << std::endl;
    }
}

int main() {
    std::cout << "CKKS Compact 512-byte Encryption Test" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << "\nTrying to find the smallest configuration that encrypts 512 bytes" << std::endl;
    std::cout << "at different security levels." << std::endl;

    std::cout << "\n\n=== Testing with 128-bit security (HEStd_128_classic) ===" << std::endl;
    // For 128-bit security, minimum ring dimension is 16384
    testConfiguration(128, 4, 16384, HEStd_128_classic, "128-bit (HEStd_128_classic)");
    testConfiguration(256, 2, 16384, HEStd_128_classic, "128-bit (HEStd_128_classic)");

    std::cout << "\n\n=== Testing with NotSet security (user-controlled) ===" << std::endl;
    std::cout << "WARNING: These configurations may not provide adequate security!" << std::endl;

    // With NotSet, we can try smaller ring dimensions
    testConfiguration(128, 4, 1024, HEStd_NotSet, "NotSet (1024 ring)");
    testConfiguration(128, 4, 2048, HEStd_NotSet, "NotSet (2048 ring)");
    testConfiguration(128, 4, 4096, HEStd_NotSet, "NotSet (4096 ring)");
    testConfiguration(256, 2, 2048, HEStd_NotSet, "NotSet (2048 ring)");
    testConfiguration(512, 1, 2048, HEStd_NotSet, "NotSet (2048 ring)");

    std::cout << "\n========================================" << std::endl;
    std::cout << "Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "For 128-bit security (HEStd_128_classic):" << std::endl;
    std::cout << "  - Minimum ring dimension: 16384" << std::endl;
    std::cout << "  - This is mandated by HE standards for security" << std::endl;
    std::cout << "\nSmaller ring dimensions are possible with HEStd_NotSet," << std::endl;
    std::cout << "but do NOT provide 128-bit security and should only be" << std::endl;
    std::cout << "used for testing/development purposes." << std::endl;

    return 0;
}
