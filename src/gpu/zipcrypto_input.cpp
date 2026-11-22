#include "zipcrypto_input.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
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
struct RawEntryMetadata {
    std::uint64_t rawOffset = 0;
    std::uint32_t crc32 = 0;
    std::uint32_t compressedSize = 0;
    std::uint32_t uncompressedSize = 0;
    std::uint16_t compressionMethod = 0;
    bool storeBoundsValid = false;
};

bool centralEntryCheckByte(const std::string& path, zip_uint64_t index,
                           std::uint8_t& checkByte, RawEntryMetadata& meta,
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
            const auto method = le16(record.data() + 10);
            const auto compressedSize = le32(record.data() + 20);
            const auto uncompressedSize = le32(record.data() + 24);
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
                le16(local.data() + 10) != dosTime ||
                le16(local.data() + 8) != method) {
                reason = "ZIP local/central encryption metadata mismatch.";
                return false;
            }
            const std::uint64_t headerSize = 30ull + le16(local.data() + 26) +
                                             le16(local.data() + 28);
            if (headerSize > size - localPos || size - localPos - headerSize < 12) {
                reason = "ZIP encrypted file header lies beyond archive.";
                return false;
            }
            meta.rawOffset = localPos + headerSize;
            meta.crc32 = crc;
            meta.compressionMethod = method;
            meta.compressedSize = compressedSize;
            meta.uncompressedSize = uncompressedSize;
            // Conservative bounds for optional STORE CRC validation only.
            // Exact ciphertext must be: 12-byte header + uncompressed payload.
            // A malformed/Zip64/overlapping entry disables the optional filter.
            meta.storeBoundsValid =
                method == 0 &&
                compressedSize != 0xffffffffu &&
                uncompressedSize != 0xffffffffu &&
                uncompressedSize > 0 &&
                compressedSize >= 12 &&
                std::uint64_t(compressedSize) == std::uint64_t(uncompressedSize) + 12 &&
                meta.rawOffset <= actualCentralStart &&
                std::uint64_t(compressedSize) <= actualCentralStart - meta.rawOffset;
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

// Maximum small STORE payload checked on GPU. Kept deliberately bounded:
// the full payload is decrypted only for candidates passing the header byte.
constexpr std::size_t kDefaultStoreCrcMaxBytes = 512;
constexpr std::size_t kAbsoluteStoreCrcMaxBytes = 4096;

std::size_t storeCrcMaxBytes() {
    const char* value = std::getenv("ZIPANALYSIS_STORE_CRC_MAX_BYTES");
    if (!value || !*value) return kDefaultStoreCrcMaxBytes;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(value, &end, 10);
    if (*end != '\0' || parsed == 0 || parsed > kAbsoluteStoreCrcMaxBytes)
        return kDefaultStoreCrcMaxBytes;
    return static_cast<std::size_t>(parsed);
}

bool prepareZipCryptoInput(const std::string& path, zip_t* archive,
                           zip_uint64_t entryIndex, ZipCryptoInput& out,
                           std::string& reason) {
    // Reset optional state even if this object gets reused.
    out = ZipCryptoInput{};
    RawEntryMetadata meta;
    if (!centralEntryCheckByte(path, entryIndex, out.checkByte, meta, reason))
        return false;

    zip_stat_t stat;
    zip_stat_init(&stat);
    const bool haveStat = zip_stat_index(archive, entryIndex, 0, &stat) == 0;
    const char* deflateToggle = std::getenv("ZIPANALYSIS_DEFLATE_PREFILTER");
    const bool wantDeflate = haveStat &&
        (stat.valid & ZIP_STAT_COMP_METHOD) &&
        stat.comp_method == ZIP_CM_DEFLATE && meta.compressionMethod == 8 &&
        !(deflateToggle && std::strcmp(deflateToggle, "0") == 0);

    const char* storeToggle = std::getenv("ZIPANALYSIS_STORE_CRC_PREFILTER");
    const bool storeRequested = !(storeToggle && std::strcmp(storeToggle, "0") == 0);
    const bool isStore = meta.compressionMethod == 0;
    bool wantStore = false;
    if (isStore) {
        if (!storeRequested) out.storeCrcSkipReason = "disabled by environment";
        else if (!haveStat || !(stat.valid & ZIP_STAT_COMP_METHOD) || stat.comp_method != 0)
            out.storeCrcSkipReason = "compression method not confirmed by libzip";
        else if (!meta.storeBoundsValid)
            out.storeCrcSkipReason = "ZIP STORE sizes/bounds are not safely verifiable";
        else if (!(stat.valid & ZIP_STAT_SIZE) || stat.size != meta.uncompressedSize)
            out.storeCrcSkipReason = "ZIP uncompressed size mismatch";
        else if (!(stat.valid & ZIP_STAT_CRC) || stat.crc != meta.crc32)
            out.storeCrcSkipReason = "ZIP CRC32 mismatch";
        else if (meta.uncompressedSize > storeCrcMaxBytes())
            out.storeCrcSkipReason = "STORE entry exceeds GPU CRC size limit";
        else wantStore = true;
    }

    // libzip 1.10+: get raw encrypted stream including ZipCrypto's 12-byte header.
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

    // For STORE request one byte past the expected end to confirm EOF.
    // Other modes retain the exact previous 12-/17-byte behavior.
    const std::size_t expectedStoreBytes = 12 + static_cast<std::size_t>(meta.uncompressedSize);
    const std::size_t requested = wantStore ? expectedStoreBytes + 1 :
                                  wantDeflate ? 17 : 12;
    std::vector<std::uint8_t> sourceData(requested, 0);
    std::size_t total = 0;
    if (zip_source_open(source) == 0) {
        while (total < requested) {
            const zip_int64_t n = zip_source_read(
                source, sourceData.data() + total, requested - total);
            if (n <= 0) break;
            total += static_cast<std::size_t>(n);
        }
        zip_source_close(source);
    }
    zip_source_free(source);
    if (total < 12) {
        reason = "Could not read ZipCrypto's 12-byte encrypted header.";
        return false;
    }
    std::copy_n(sourceData.begin(), 12, out.encryptedHeader.begin());

    // Compare independent raw-file bytes against libzip's encrypted source.
    std::ifstream f(std::filesystem::u8path(path), std::ios::binary);
    std::array<std::uint8_t, 12> actualHeader{};
    if (!f || !readAt(f, meta.rawOffset, actualHeader.data(), actualHeader.size()) ||
        actualHeader != out.encryptedHeader) {
        reason = "Raw encrypted ZIP header does not match libzip source data.";
        return false;
    }
    if (wantStore) {
        // Source length must exactly match central-directory sizes, and ALL
        // ciphertext bytes must match disk before enabling exact CRC checking.
        std::vector<std::uint8_t> actualPayload(meta.uncompressedSize);
        if (total != expectedStoreBytes ||
            !readAt(f, meta.rawOffset + 12, actualPayload.data(), actualPayload.size()) ||
            !std::equal(actualPayload.begin(), actualPayload.end(), sourceData.begin() + 12)) {
            out.storeCrcSkipReason = "encrypted STORE payload/source mismatch";
        } else {
            out.encryptedStoreData = std::move(actualPayload);
            out.storeExpectedCrc32 = meta.crc32;
            out.storeCrcPrefilterEnabled = true;
            out.storeCrcSkipReason.clear();
        }
    }
    if (wantDeflate && total == 17) {
        std::array<std::uint8_t, 5> raw{};
        if (readAt(f, meta.rawOffset + 12, raw.data(), raw.size()) &&
            std::equal(raw.begin(), raw.end(), sourceData.begin() + 12)) {
            out.encryptedDeflatePrefix = raw;
            out.deflatePrefilterEnabled = true;
        }
    }
    return true;
}
