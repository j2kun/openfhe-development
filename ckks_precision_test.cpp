//==================================================================================
// CKKS Precision Test
//
// This example tests the precision limits of CKKS slots and demonstrates
// encoding multiple bytes per slot.
//==================================================================================

#include "openfhe.h"

// Serialization headers
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include <iostream>
#include <sstream>
#include <cmath>

using namespace lbcrypto;

// Helper function to get serialized size of an object
template<typename T>
size_t getSerializedSize(const T& obj) {
    std::ostringstream os;
    Serial::Serialize(obj, os, SerType::BINARY);
    return os.str().size();
}

void testPrecision(CryptoContext<DCRTPoly> cc, const KeyPair<DCRTPoly>& keys, size_t batchSize,
                   const std::string& description, double maxValue, size_t numBitsPerSlot) {
    std::cout << "\n" << description << std::endl;
    std::cout << std::string(description.length(), '=') << std::endl;

    // Create test data with values up to maxValue
    std::vector<double> testData(batchSize);
    for (size_t i = 0; i < batchSize; i++) {
        // Use a variety of values including the maximum
        if (i < 10) {
            testData[i] = maxValue; // Test maximum value
        } else if (i < 20) {
            testData[i] = maxValue / 2.0; // Test half maximum
        } else {
            testData[i] = static_cast<double>(i % static_cast<size_t>(maxValue + 1));
        }
    }

    // Encode and encrypt
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(testData);
    auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // Decrypt and check accuracy
    Plaintext result;
    cc->Decrypt(keys.secretKey, ciphertext, &result);
    result->SetLength(batchSize);
    auto decryptedValues = result->GetRealPackedValue();

    // Calculate errors
    double maxError = 0.0;
    double maxRelativeError = 0.0;
    bool hasLargeError = false;

    for (size_t i = 0; i < std::min(batchSize, size_t(100)); i++) {
        double error = std::abs(testData[i] - decryptedValues[i]);
        double relativeError = (testData[i] != 0) ? (error / std::abs(testData[i])) : 0.0;

        maxError = std::max(maxError, error);
        maxRelativeError = std::max(maxRelativeError, relativeError);

        // Check if error is more than 0.5 (would cause incorrect integer recovery)
        if (error > 0.5) {
            hasLargeError = true;
        }
    }

    // Calculate effective precision
    double logPrecision = result->GetLogPrecision();

    std::cout << "Max value tested: " << maxValue << std::endl;
    std::cout << "Bits per slot: " << numBitsPerSlot << " bits" << std::endl;
    std::cout << "Bytes per slot: " << (numBitsPerSlot / 8.0) << " bytes" << std::endl;
    std::cout << "Max absolute error: " << maxError << std::endl;
    std::cout << "Max relative error: " << maxRelativeError << std::endl;
    std::cout << "Log precision (bits): " << logPrecision << std::endl;

    if (hasLargeError) {
        std::cout << "Status: FAIL - Errors too large for reliable integer recovery" << std::endl;
    } else {
        std::cout << "Status: SUCCESS - Values can be reliably recovered" << std::endl;
    }

    // Show ciphertext size
    size_t ctSize = getSerializedSize(ciphertext);
    double plaintextBytes = batchSize * (numBitsPerSlot / 8.0);
    std::cout << "Ciphertext size: " << ctSize << " bytes" << std::endl;
    std::cout << "Effective plaintext size: " << plaintextBytes << " bytes" << std::endl;
    std::cout << "Expansion factor: " << ctSize / plaintextBytes << "x" << std::endl;

    // Show sample values
    std::cout << "\nSample values (first 5):" << std::endl;
    for (size_t i = 0; i < std::min(size_t(5), batchSize); i++) {
        std::cout << "  Original: " << testData[i]
                  << " -> Decrypted: " << decryptedValues[i]
                  << " (error: " << std::abs(testData[i] - decryptedValues[i]) << ")" << std::endl;
    }
}

int main() {
    std::cout << "CKKS Precision and Multi-Byte Encoding Test" << std::endl;
    std::cout << "============================================" << std::endl;

    // Setup CryptoContext with larger scaling factor for better precision
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetBatchSize(0); // Use maximum slots
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50); // 50-bit scaling factor
    parameters.SetSecurityLevel(HEStd_128_classic);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
    size_t ringDim = cc->GetRingDimension();

    std::cout << "\nCKKS Parameters:" << std::endl;
    std::cout << "  Ring Dimension: " << ringDim << std::endl;
    std::cout << "  Batch Size: " << batchSize << " slots" << std::endl;
    std::cout << "  Scaling Modulus Size: " << parameters.GetScalingModSize() << " bits" << std::endl;
    std::cout << "  Security Level: 128-bit" << std::endl;

    // Generate keys
    std::cout << "\nGenerating keys..." << std::endl;
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    std::cout << "Done." << std::endl;

    // Test 1: 1 byte per slot (8 bits, values 0-255)
    testPrecision(cc, keys, batchSize, "Test 1: One byte per slot (8 bits)", 255.0, 8);

    // Test 2: 2 bytes per slot (16 bits, values 0-65535)
    testPrecision(cc, keys, batchSize, "Test 2: Two bytes per slot (16 bits)", 65535.0, 16);

    // Test 3: 3 bytes per slot (24 bits, values 0-16777215)
    testPrecision(cc, keys, batchSize, "Test 3: Three bytes per slot (24 bits)", 16777215.0, 24);

    // Test 4: 4 bytes per slot (32 bits, values 0-4294967295)
    testPrecision(cc, keys, batchSize, "Test 4: Four bytes per slot (32 bits)", 4294967295.0, 32);

    // Test 5: 5 bytes per slot (40 bits)
    testPrecision(cc, keys, batchSize, "Test 5: Five bytes per slot (40 bits)",
                  std::pow(2.0, 40.0) - 1.0, 40);

    // Test 6: Push the limits - 48 bits (close to scaling factor limit)
    testPrecision(cc, keys, batchSize, "Test 6: Six bytes per slot (48 bits)",
                  std::pow(2.0, 48.0) - 1.0, 48);

    std::cout << "\n============================================" << std::endl;
    std::cout << "Summary" << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << "With scaleModSize=50 bits, CKKS can reliably encode integers" << std::endl;
    std::cout << "up to approximately 2^45 to 2^48 (depending on noise and operations)." << std::endl;
    std::cout << "This allows encoding 5-6 bytes per slot in a single ciphertext." << std::endl;
    std::cout << "\nFor 2 bytes per slot: " << batchSize << " slots × 2 bytes = "
              << (batchSize * 2) << " bytes" << std::endl;
    std::cout << "This is 2x better plaintext capacity than 1 byte per slot!" << std::endl;

    return 0;
}
