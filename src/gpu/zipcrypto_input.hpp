#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <zip.h>

// The 12 ciphertext bytes precede the compressed data in traditional ZipCrypto.
// checkByte is the high CRC byte, or high DOS-time byte when the data-descriptor flag is set.
struct ZipCryptoInput {
    std::array<std::uint8_t, 12> encryptedHeader{};
    std::uint8_t checkByte = 0;
};

// Returns false to request CPU fallback. Never guess a check byte when metadata
// cannot be read reliably; guessing would silently miss valid passwords.
bool prepareZipCryptoInput(const std::string& path,
                           zip_t* archive,
                           zip_uint64_t entryIndex,
                           ZipCryptoInput& out,
                           std::string& reason);
