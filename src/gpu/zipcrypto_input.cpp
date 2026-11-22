#include "zipcrypto_input.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <vector>

namespace {
std::uint16_t le16(const std::uint8_t* p) {
    return std::uint16_t(p[0]) | (std::uint16_t(p[1]) << 8);
}
std::uint32_t le32(const std::uint8_t* p) {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) |
           (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}
bool readAt(std::ifstream& f, std::uint64_t offset, void* dest, std::size_t len) {
    if (offset > std::uint64_t(std::numeric_limits<std::streamoff>::max())) return false;
    f.clear();
    f.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    return f.good() && static_cast<bool>(f.read(static_cast<char*>(dest),
                                                  static_cast<std::streamsize>(len)));
}

// This reader deliberately supports only classic single-disk central directories.
// SFX data preceding a classic ZIP is handled by determining the prefix offset.
// Zip64/multi-disk archives fall back to the CPU path (no false negatives).
bool centralEntryCheckByte(const std::string& path, zip_uint64_t index,
                           std::uint8_t& checkByte, std::uint64_t& rawOffset,
                           std::string& reason) {
    std::ifstream f(std::filesystem::u8path(path), std::ios::binary);
    if (!f) { reason = "Cannot read ZIP metadata for GPU."; return false; }
    f.seekg(0, std::ios::end);
    const auto endPos = f.tellg();
    if (endPos < 22) { reason = "ZIP metadata is too short."; return false; }
    const auto size = static_cast<std::uint64_t>(endPos);
    const std::uint64_t searchLen = std::min<std::uint64_t>(size, 65557);
    std::vector<std::uint8_t> tail(static_cast<std::size_t>(searchLen));
    if (!readAt(f, size - searchLen, tail.data(), tail.size())) {
        reason = "Cannot read end-of-central-directory record."; return false;
    }
    bool foundEocd = false;
    std::uint64_t eocdPos = 0;
    std::array<std::uint8_t, 22> eocd{};
    for (std::size_t pos = tail.size() - 22;; --pos) {
        if (le32(tail.data() + pos) == 0x06054b50u &&
            pos + 22 + le16(tail.data() + pos + 20) == tail.size()) {
            std::copy_n(tail.data() + pos, 22, eocd.data());
            eocdPos = size - searchLen + pos;
            foundEocd = true;
            break;
        }
        if (pos == 0) break;
    }
    if (!foundEocd) { reason = "Cannot locate a classic ZIP directory."; return false; }

    const auto entriesOnDisk = le16(eocd.data() + 8);
    const auto entriesTotal = le16(eocd.data() + 10);
    const auto centralSize = le32(eocd.data() + 12);
    const auto centralOffset = le32(eocd.data() + 16);
    if (le16(eocd.data() + 4) != 0 || le16(eocd.data() + 6) != 0 ||
        entriesOnDisk != entriesTotal || entriesTotal == 0xffffu ||
        centralSize == 0xffffffffu || centralOffset == 0xffffffffu) {
        reason = "GPU metadata reader does not support Zip64/multi-disk ZIP.";
        return false;
    }
    if (index >= entriesTotal || eocdPos < centralSize) {
        reason = "Invalid ZIP central-directory bounds."; return false;
    }
    const std::uint64_t actualCentralStart = eocdPos - centralSize;
    if (actualCentralStart < centralOffset) {
        reason = "Unsupported ZIP directory offset layout."; return false;
    }
    const std::uint64_t prefixBytes = actualCentralStart - centralOffset;
    std::uint64_t cursor = actualCentralStart;
    for (std::uint64_t i = 0; i <= index; ++i) {
        std::array<std::uint8_t, 46> record{};
        if (cursor > eocdPos || eocdPos - cursor < record.size() ||
            !readAt(f, cursor, record.data(), record.size()) ||
            le32(record.data()) != 0x02014b50u) {
            reason = "Invalid ZIP central-directory entry."; return false;
        }
        const std::uint64_t recLen = 46ull + le16(record.data() + 28) +
                                     le16(record.data() + 30) + le16(record.data() + 32);
        if (recLen > eocdPos - cursor) {
            reason = "ZIP central-directory entry exceeds its bounds."; return false;
        }
        if (i == index) {
            const auto flags = le16(record.data() + 8);
            const auto dosTime = le16(record.data() + 12);
            const auto crc = le32(record.data() + 16);
            const auto localOffset = le32(record.data() + 42);
            if (!(flags & 1) || localOffset == 0xffffffffu) {
                reason = "GPU entry is not classic ZipCrypto metadata."; return false;
            }
            const std::uint64_t localPos = prefixBytes + localOffset;
            std::array<std::uint8_t, 30> local{};
            if (localPos >= size || size - localPos < local.size() ||
                !readAt(f, localPos, local.data(), local.size()) ||
                le32(local.data()) != 0x04034b50u) {
                reason = "Cannot confirm ZIP local header for GPU."; return false;
            }
            const auto localFlags = le16(local.data() + 6);
            if (!(localFlags & 1) || ((localFlags ^ flags) & 8) != 0 ||
                le16(local.data() + 10) != dosTime) {
                reason = "ZIP local/central encryption metadata mismatch.";
                return false;
            }
            const std::uint64_t headerSize = 30ull + le16(local.data() + 26) +
                                             le16(local.data() + 28);
            if (headerSize > size - localPos || size - localPos - headerSize < 12) {
                reason = "ZIP encrypted file header lies beyond archive.";
                return false;
            }
            rawOffset = localPos + headerSize;
            checkByte = (flags & 8) ? std::uint8_t(dosTime >> 8)
                                    : std::uint8_t(crc >> 24);
            return true;
        }
        cursor += recLen;
    }
    reason = "Unable to find selected ZIP entry.";
    return false;
}
} // namespace

bool prepareZipCryptoInput(const std::string& path, zip_t* archive,
                           zip_uint64_t entryIndex, ZipCryptoInput& out,
                           std::string& reason) {
    std::uint64_t rawOffset = 0;
    if (!centralEntryCheckByte(path, entryIndex, out.checkByte, rawOffset, reason))
        return false;

    // Requires libzip >= 1.10.0. ENCRYPTED is the raw ciphertext stream,
    // including the 12-byte ZipCrypto encryption header.
    zip_error_t error;
    zip_error_init(&error);
    zip_source_t* source = zip_source_zip_file_create(
        archive, entryIndex, ZIP_FL_ENCRYPTED | ZIP_FL_UNCHANGED,
        0, -1, nullptr, &error);
    if (!source) {
        reason = "Cannot access encrypted ZIP stream: " +
                 std::string(zip_error_strerror(&error));
        zip_error_fini(&error);
        return false;
    }
    zip_error_fini(&error);

    bool ok = false;
    if (zip_source_open(source) == 0) {
        std::size_t total = 0;
        while (total < out.encryptedHeader.size()) {
            const zip_int64_t n = zip_source_read(
                source, out.encryptedHeader.data() + total,
                out.encryptedHeader.size() - total);
            if (n <= 0) break;
            total += static_cast<std::size_t>(n);
        }
        ok = total == out.encryptedHeader.size();
        zip_source_close(source);
    }
    zip_source_free(source);
    if (!ok) {
        reason = "Could not read ZipCrypto's 12-byte encrypted header.";
        return false;
    }
    // Sanity check: the source API must have returned the encrypted header,
    // not the compressed data or a transformed stream. If not, use CPU.
    std::ifstream f(std::filesystem::u8path(path), std::ios::binary);
    std::array<std::uint8_t, 12> actual{};
    if (!f || !readAt(f, rawOffset, actual.data(), actual.size()) ||
        actual != out.encryptedHeader) {
        reason = "Raw encrypted ZIP header does not match libzip source data.";
        return false;
    }
    return true;
}
