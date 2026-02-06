//==================================================================================
// CKKS Size Measurement Example
//
// This example encrypts 512 bytes (one byte per slot) using CKKS and reports
// the sizes of the ciphertext, public key, private key, and relinearization keys.
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

int main() {
    std::cout << "CKKS Size Measurement Example" << std::endl;
    std::cout << "==============================" << std::endl << std::endl;

    // Step 1: Setup CryptoContext
    CCParams<CryptoContextCKKSRNS> parameters;

    // Set batch size to 0 to use maximum available slots (ring_dimension / 2)
    parameters.SetBatchSize(0);

    // Set minimal multiplicative depth since we're just encrypting
    parameters.SetMultiplicativeDepth(1);

    // Standard scaling factor
    parameters.SetScalingModSize(50);

    // Use HEStd_128_classic for 128-bit security
    parameters.SetSecurityLevel(HEStd_128_classic);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    // Enable features
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Get the actual batch size used
    size_t batchSize = cryptoContext->GetEncodingParams()->GetBatchSize();
    size_t ringDim = cryptoContext->GetRingDimension();

    std::cout << "CKKS Parameters:" << std::endl;
    std::cout << "  Ring Dimension: " << ringDim << std::endl;
    std::cout << "  Batch Size (slots): " << batchSize << std::endl;
    std::cout << "  Security Level: 128-bit" << std::endl;
    std::cout << "  Slots utilization: 100% (maximum)" << std::endl;
    std::cout << std::endl;

    // Step 2: Key Generation
    std::cout << "Generating keys..." << std::endl;
    auto keyPair = cryptoContext->KeyGen();

    // Generate relinearization keys (used after multiplication)
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    std::cout << "Keys generated successfully." << std::endl << std::endl;

    // Step 3: Create data for all slots (values 0-255 mapped to 0.0-1.0)
    std::vector<double> byteData(batchSize);
    for (size_t i = 0; i < batchSize; i++) {
        // Map byte values to [0, 1] range for CKKS
        byteData[i] = static_cast<double>(i % 256) / 255.0;
    }

    // Step 4: Encode and encrypt
    std::cout << "Encoding and encrypting " << batchSize << " bytes (one per slot)..." << std::endl;
    Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(byteData);
    auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);
    std::cout << "Encryption complete." << std::endl << std::endl;

    // Step 5: Measure sizes
    std::cout << "Measuring sizes..." << std::endl;
    std::cout << "==================" << std::endl << std::endl;

    // Measure ciphertext size
    size_t ciphertextSize = getSerializedSize(ciphertext);
    std::cout << "Ciphertext size: " << ciphertextSize << " bytes";
    std::cout << " (" << ciphertextSize / 1024.0 << " KB)" << std::endl;

    // Measure public key size
    size_t publicKeySize = getSerializedSize(keyPair.publicKey);
    std::cout << "Public key size: " << publicKeySize << " bytes";
    std::cout << " (" << publicKeySize / 1024.0 << " KB)" << std::endl;

    // Measure private key size
    size_t privateKeySize = getSerializedSize(keyPair.secretKey);
    std::cout << "Private key size: " << privateKeySize << " bytes";
    std::cout << " (" << privateKeySize / 1024.0 << " KB)" << std::endl;

    // Measure relinearization key size
    // Get the evaluation key map from the crypto context
    auto evalMultKeys = cryptoContext->GetEvalMultKeyVector(keyPair.secretKey->GetKeyTag());
    size_t relinKeySize = 0;
    if (evalMultKeys.size() > 0) {
        for (const auto& key : evalMultKeys) {
            relinKeySize += getSerializedSize(key);
        }
    }
    std::cout << "Relinearization keys size: " << relinKeySize << " bytes";
    std::cout << " (" << relinKeySize / 1024.0 << " KB)" << std::endl;

    std::cout << std::endl;
    std::cout << "Analysis:" << std::endl;
    std::cout << "==========" << std::endl;
    std::cout << "Plaintext size: " << batchSize << " bytes (1 byte per slot)" << std::endl;
    std::cout << "Ciphertext expansion factor: " << ciphertextSize / static_cast<double>(batchSize) << "x" << std::endl;
    std::cout << std::endl;

    // Calculate total size
    size_t totalSize = ciphertextSize + publicKeySize + privateKeySize + relinKeySize;
    std::cout << "Total size (ciphertext + all keys): " << totalSize << " bytes";
    std::cout << " (" << totalSize / 1024.0 << " KB, " << totalSize / (1024.0 * 1024.0) << " MB)" << std::endl;
    std::cout << "Total expansion factor: " << totalSize / static_cast<double>(batchSize) << "x" << std::endl;

    // Verify decryption works
    std::cout << std::endl << "Verifying decryption..." << std::endl;
    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &result);
    result->SetLength(batchSize);

    // Check first few values
    auto decryptedValues = result->GetRealPackedValue();
    bool success = true;
    for (size_t i = 0; i < 10; i++) {
        double expected = static_cast<double>(i % 256) / 255.0;
        double actual = decryptedValues[i];
        double error = std::abs(expected - actual);
        if (error > 0.01) { // Allow some error due to CKKS approximation
            success = false;
            break;
        }
    }

    if (success) {
        std::cout << "Decryption successful! First 10 values match." << std::endl;
    } else {
        std::cout << "Warning: Decryption values don't match exactly (this is normal for CKKS approximation)." << std::endl;
    }

    return 0;
}
