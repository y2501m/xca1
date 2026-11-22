#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <zip.h>

// The 12 ciphertext bytes precede the compressed data in traditional ZipCrypto.
// checkByte is the high CRC byte, or high DOS-time byte when the data-descriptor flag is set.
struct ZipCryptoInput {
    std::array<std::uint8_t, 12> encryptedHeader{};
    std::uint8_t checkByte = 0;

    // Valid only when deflatePrefilterEnabled is true. These are encrypted bytes
    // AFTER the 12-byte ZipCrypto header, not decrypted compressed data.
    std::array<std::uint8_t, 5> encryptedDeflatePrefix{};
    bool deflatePrefilterEnabled = false;

    // Optional exact check for small, uncompressed (STORE/method 0) entries.
    // These bytes are encrypted, start immediately after the 12-byte header,
    // and are used ONLY when storeCrcPrefilterEnabled is true.
    std::vector<std::uint8_t> encryptedStoreData;
    std::uint32_t storeExpectedCrc32 = 0;
    bool storeCrcPrefilterEnabled = false;
    std::string storeCrcSkipReason;
};

// Returns false to request CPU fallback. Never guess a check byte when metadata
// cannot be read reliably; guessing would silently miss valid passwords.
bool prepareZipCryptoInput(const std::string& path,
                           zip_t* archive,
                           zip_uint64_t entryIndex,
                           ZipCryptoInput& out,
                           std::string& reason);
