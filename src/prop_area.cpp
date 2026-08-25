#include "prop_area.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <linux/futex.h>
#include <sys/syscall.h>
#endif

namespace resetprop {

namespace {

constexpr std::uint32_t kPropAreaMagic = 0x504f5250;
constexpr std::uint32_t kPropAreaVersion = 0xfc6ed0ab;
constexpr std::uint32_t kPropValueMax = 92;
constexpr std::uint32_t kPropInfoLongFlag = 1u << 16;
constexpr std::uint32_t kLongLegacyErrorBufferSize = 56;
constexpr const char* kLongLegacyError = "Must use __system_property_read_callback() to read";

struct RawPropAreaHeader {
    std::uint32_t bytes_used;
    std::uint32_t serial;
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t reserved[28];
};

struct RawTrieNodeHeader {
    std::uint32_t namelen;
    std::uint32_t prop;
    std::uint32_t left;
    std::uint32_t right;
    std::uint32_t children;
};

struct RawLongProperty {
    char error_message[kLongLegacyErrorBufferSize];
    std::uint32_t offset;
};

struct RawPropInfoHeader {
    std::uint32_t serial;
    char value[kPropValueMax];
};

static_assert(sizeof(RawPropAreaHeader) == 128, "Unexpected prop_area header size");
static_assert(sizeof(RawTrieNodeHeader) == 20, "Unexpected trie node header size");
static_assert(sizeof(RawLongProperty) == 60, "Unexpected long property size");
static_assert(sizeof(RawPropInfoHeader) == 96, "Unexpected prop_info header size");

constexpr std::uint32_t kPropAreaHeaderSize = sizeof(RawPropAreaHeader);
constexpr std::uint32_t kTrieNodeHeaderSize = sizeof(RawTrieNodeHeader);
constexpr std::uint32_t kPropInfoSize = sizeof(RawPropInfoHeader);
constexpr std::uint32_t kPropAreaSerialOffset = offsetof(RawPropAreaHeader, serial);
constexpr std::uint32_t kLongOffsetInInfo =
    offsetof(RawPropInfoHeader, value) + offsetof(RawLongProperty, offset);
constexpr std::uint32_t kDirtyBackupSize = (kPropValueMax + 3u) & ~3u;
constexpr std::uint32_t kInitialBytesUsed = kTrieNodeHeaderSize + kDirtyBackupSize;

constexpr std::uint32_t kNodePropOffset = offsetof(RawTrieNodeHeader, prop);
constexpr std::uint32_t kNodeLeftOffset = offsetof(RawTrieNodeHeader, left);
constexpr std::uint32_t kNodeRightOffset = offsetof(RawTrieNodeHeader, right);
constexpr std::uint32_t kNodeChildrenOffset = offsetof(RawTrieNodeHeader, children);

constexpr std::uint32_t align_up(std::uint32_t value, std::uint32_t align) {
    if (align == 0) {
        return value;
    }
    const std::uint32_t mask = align - 1;
    return (value + mask) & ~mask;
}

std::string format_errno(const std::string& prefix, const std::string& path) {
    return prefix + " " + path + ": " + std::strerror(errno);
}

void futex_wake_all(const std::uint32_t* addr) {
#if defined(__linux__)
    (void)syscall(SYS_futex, addr, FUTEX_WAKE, INT_MAX, nullptr, nullptr, 0);
#else
    (void)addr;
#endif
}

bool collect_regular_files(const std::string& root, std::vector<std::string>* files,
                           std::string* error) {
    DIR* dir = opendir(root.c_str());
    if (dir == nullptr) {
        *error = format_errno("failed to open directory", root);
        return false;
    }

    while (true) {
        errno = 0;
        dirent* entry = readdir(dir);
        if (entry == nullptr) {
            if (errno != 0) {
                *error = format_errno("failed to read directory", root);
                closedir(dir);
                return false;
            }
            break;
        }

        if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        const std::string path = root + "/" + entry->d_name;
        struct stat st{};
        if (lstat(path.c_str(), &st) != 0) {
            *error = format_errno("failed to stat", path);
            closedir(dir);
            return false;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!collect_regular_files(path, files, error)) {
                closedir(dir);
                return false;
            }
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            files->push_back(path);
        }
    }

    closedir(dir);
    return true;
}

bool collect_prop_area_targets(const std::string& root, std::vector<std::string>* files,
                               std::string* error) {
    struct stat st{};
    if (lstat(root.c_str(), &st) != 0) {
        *error = format_errno("failed to stat", root);
        return false;
    }
    if (S_ISREG(st.st_mode)) {
        files->push_back(root);
        return true;
    }
    if (S_ISDIR(st.st_mode)) {
        return collect_regular_files(root, files, error);
    }
    *error = "unsupported prop-area root: " + root;
    return false;
}

std::vector<std::string> split_segments(const std::string& key) {
    std::vector<std::string> segments;
    std::size_t start = 0;
    while (start <= key.size()) {
        const std::size_t end = key.find('.', start);
        const std::size_t len = (end == std::string::npos ? key.size() : end) - start;
        segments.emplace_back(key.substr(start, len));
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return segments;
}

int cmp_prop_name(const std::string& left, const std::string& right) {
    if (left.size() < right.size()) {
        return -1;
    }
    if (left.size() > right.size()) {
        return 1;
    }
    const int cmp = std::memcmp(left.data(), right.data(), left.size());
    if (cmp < 0) {
        return -1;
    }
    if (cmp > 0) {
        return 1;
    }
    return 0;
}

struct TrieNodeRecord {
    std::uint32_t offset = 0;
    std::uint32_t namelen = 0;
    std::uint32_t prop = 0;
    std::uint32_t left = 0;
    std::uint32_t right = 0;
    std::uint32_t children = 0;
    std::string name;
};

struct PropRecord {
    std::string name;
    std::string value;
    std::uint32_t prop_offset = 0;
    std::uint32_t value_offset = 0;
    bool is_long = false;
};

struct CompactRecord {
    std::uint32_t offset = 0;
    std::uint32_t aligned_size = 0;
    std::optional<std::uint32_t> referer_data;
    std::optional<std::uint32_t> refer_off;
    std::optional<std::uint32_t> long_ref_prop;
};

CompactRecord make_compact_record(std::uint32_t offset, std::uint32_t aligned_size,
                                  std::optional<std::uint32_t> referer_data = std::nullopt,
                                  std::optional<std::uint32_t> refer_off = std::nullopt,
                                  std::optional<std::uint32_t> long_ref_prop = std::nullopt) {
    CompactRecord record;
    record.offset = offset;
    record.aligned_size = aligned_size;
    record.referer_data = referer_data;
    record.refer_off = refer_off;
    record.long_ref_prop = long_ref_prop;
    return record;
}

class PropAreaFile {
public:
    PropAreaFile() = default;
    ~PropAreaFile() {
        if (map_ != nullptr && map_ != MAP_FAILED) {
            munmap(map_, map_size_);
        }
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    bool load(const std::string& path, std::string* error) {
        path_ = path;
        fd_ = open(path.c_str(), O_RDWR | O_CLOEXEC);
        if (fd_ < 0) {
            *error = format_errno("failed to open", path);
            return false;
        }

        struct stat st{};
        if (fstat(fd_, &st) != 0) {
            *error = "fstat failed: " + std::string(std::strerror(errno));
            return false;
        }
        if (st.st_size < 0) {
            *error = "negative file size";
            return false;
        }
        map_size_ = static_cast<std::size_t>(st.st_size);
        map_ = static_cast<std::uint8_t*>(
            mmap(nullptr, map_size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0));
        if (map_ == MAP_FAILED) {
            map_ = nullptr;
            *error = "mmap failed: " + std::string(std::strerror(errno));
            return false;
        }

        valid_ = validate_header();
        return true;
    }

    bool valid() const { return valid_; }

    bool bump_area_serial(std::string* error) {
        if (map_size_ < kPropAreaSerialOffset + sizeof(std::uint32_t)) {
            *error = "prop area header is truncated";
            return false;
        }
        const std::size_t absolute_offset = kPropAreaSerialOffset;
        auto* serial_ptr = reinterpret_cast<std::uint32_t*>(map_ + absolute_offset);
        const std::uint32_t old_serial = __atomic_load_n(serial_ptr, __ATOMIC_RELAXED);
        __atomic_store_n(serial_ptr, old_serial + 1u, __ATOMIC_RELEASE);
        futex_wake_all(serial_ptr);
        dirty_ = true;
        return true;
    }

    bool has_property(const std::string& key, bool* found, std::string* error) {
        *found = false;
        std::uint32_t node_offset = 0;
        if (!traverse_trie(key, &node_offset, error)) {
            return false;
        }
        if (node_offset == kInvalidOffset) {
            return true;
        }
        std::uint32_t prop_offset = 0;
        if (!read_u32_data(node_offset + kNodePropOffset, &prop_offset, error)) {
            return false;
        }
        *found = (prop_offset != 0);
        return true;
    }

    bool set_property(const std::string& key, const std::string& value, bool* created,
                      std::string* error) {
        *created = false;

        std::uint32_t node_offset = 0;
        if (!ensure_traverse_trie(key, &node_offset, error)) {
            return false;
        }

        std::uint32_t prop_offset = 0;
        if (!read_u32_data(node_offset + kNodePropOffset, &prop_offset, error)) {
            return false;
        }

        const bool use_long = value.size() >= kPropValueMax;
        const std::uint32_t serial_len =
            use_long ? static_cast<std::uint32_t>(std::strlen(kLongLegacyError))
                     : static_cast<std::uint32_t>(value.size());

        if (prop_offset == 0) {
            std::uint32_t new_prop_offset = 0;
            if (!create_prop_info(key, value, &new_prop_offset, error) ||
                !store_u32_data_relaxed(new_prop_offset,
                                        compose_initial_serial(serial_len, use_long), error) ||
                !store_u32_data_release(node_offset + kNodePropOffset, new_prop_offset, error)) {
                return false;
            }
            dirty_ = true;
            *created = true;
            return true;
        }

        PropRecord record;
        if (!read_prop_record(prop_offset, &record, error)) {
            return false;
        }

        std::uint32_t old_serial = 0;
        if (!read_u32_data(prop_offset, &old_serial, error)) {
            return false;
        }

        bool recreate = false;
        if (record.is_long) {
            recreate = value.size() > record.value.size();
        } else {
            recreate = value.size() >= kPropValueMax;
        }

        if (recreate) {
            if (!store_u32_data_release(node_offset + kNodePropOffset, 0, error) ||
                !wipe_prop_info(prop_offset, error)) {
                return false;
            }
            std::uint32_t new_prop_offset = 0;
            if (!create_prop_info(key, value, &new_prop_offset, error) ||
                !store_u32_data_relaxed(new_prop_offset,
                                        compose_initial_serial(serial_len, use_long), error) ||
                !store_u32_data_release(node_offset + kNodePropOffset, new_prop_offset, error)) {
                return false;
            }
            dirty_ = true;
            *created = true;
            return true;
        }

        const std::uint32_t serial_dirty = old_serial | 1u;
        if (!store_u32_data_relaxed(prop_offset, serial_dirty, error)) {
            return false;
        }

        if (record.is_long) {
            if (!update_long_property(prop_offset, record, value, error)) {
                return false;
            }
        } else if (!update_inline_property(prop_offset, value, error)) {
            return false;
        }

        __atomic_thread_fence(__ATOMIC_RELEASE);
        const std::size_t serial_absolute_offset =
            kPropAreaHeaderSize + static_cast<std::size_t>(prop_offset);
        if (!store_u32_abs_relaxed(serial_absolute_offset,
                                   compose_visible_serial(serial_dirty, serial_len, record.is_long),
                                   error)) {
            return false;
        }
        futex_wake_all(reinterpret_cast<const std::uint32_t*>(map_ + serial_absolute_offset));
        __atomic_thread_fence(__ATOMIC_RELEASE);
        if (!store_u32_abs_relaxed(serial_absolute_offset,
                                   compose_hidden_serial(serial_dirty, serial_len, record.is_long),
                                   error)) {
            return false;
        }

        dirty_ = true;
        return true;
    }

    bool delete_property(const std::string& key, bool* deleted, std::string* error) {
        *deleted = false;

        std::uint32_t node_offset = 0;
        if (!traverse_trie(key, &node_offset, error)) {
            return false;
        }
        if (node_offset == kInvalidOffset) {
            return true;
        }

        std::uint32_t prop_offset = 0;
        if (!read_u32_data(node_offset + kNodePropOffset, &prop_offset, error)) {
            return false;
        }
        if (prop_offset == 0) {
            return true;
        }

        if (!write_u32_data(node_offset + kNodePropOffset, 0, error)) {
            return false;
        }
        if (!wipe_prop_info(prop_offset, error)) {
            return false;
        }
        bool pruned = false;
        if (!prune_trie(0, &pruned, error)) {
            return false;
        }
        *deleted = true;
        dirty_ = true;
        return true;
    }

    bool compact(bool* changed, std::string* error) {
        *changed = false;

        std::uint32_t bytes_used = 0;
        if (!get_bytes_used(&bytes_used, error)) {
            return false;
        }

        const bool has_dirty = has_dirty_backup(error);
        if (!error->empty()) {
            return false;
        }

        std::vector<CompactRecord> records;
        if (has_dirty) {
            records.push_back(make_compact_record(kTrieNodeHeaderSize, kDirtyBackupSize));
        }

        std::set<std::uint32_t> seen_nodes;
        std::set<std::uint32_t> seen_props;
        std::set<std::uint32_t> seen_longs;
        if (!collect_compact_records_from(0, std::nullopt, std::nullopt, &seen_nodes, &seen_props,
                                          &seen_longs, &records, error)) {
            return false;
        }

        std::sort(records.begin(), records.end(),
                  [](const CompactRecord& lhs, const CompactRecord& rhs) {
                      return lhs.offset < rhs.offset;
                  });

        const std::uint32_t initial = has_dirty ? kInitialBytesUsed : kTrieNodeHeaderSize;
        std::uint32_t cursor = initial;
        std::size_t first_hole_index = records.size();
        for (std::size_t i = 0; i < records.size(); ++i) {
            const auto& record = records[i];
            if (record.offset > cursor) {
                first_hole_index = i;
                break;
            }
            const std::uint32_t end = record.offset + record.aligned_size;
            if (end > cursor) {
                cursor = end;
            }
        }

        if (first_hole_index == records.size()) {
            if (cursor < bytes_used) {
                if (!write_bytes_used(cursor, error)) {
                    return false;
                }
                dirty_ = true;
                *changed = true;
            }
            return true;
        }

        std::unordered_map<std::uint32_t, std::uint32_t> remap;
        std::uint32_t new_cursor = cursor;
        for (std::size_t i = first_hole_index; i < records.size(); ++i) {
            remap.emplace(records[i].offset, new_cursor);
            new_cursor += records[i].aligned_size;
        }

        for (std::size_t i = first_hole_index; i < records.size(); ++i) {
            const auto& record = records[i];
            const std::uint32_t new_offset = remap[record.offset];

            if (record.referer_data.has_value() && record.refer_off.has_value()) {
                const auto referer_it = remap.find(*record.referer_data);
                const std::uint32_t referer_data =
                    referer_it == remap.end() ? *record.referer_data : referer_it->second;
                const std::uint32_t field_offset = referer_data + *record.refer_off;
                std::uint32_t field_value = new_offset;
                if (record.long_ref_prop.has_value()) {
                    const auto prop_it = remap.find(*record.long_ref_prop);
                    const std::uint32_t prop_offset =
                        prop_it == remap.end() ? *record.long_ref_prop : prop_it->second;
                    field_value = new_offset - prop_offset;
                }
                if (!write_u32_data(field_offset, field_value, error)) {
                    return false;
                }
            }

            if (new_offset != record.offset) {
                std::vector<std::uint8_t> chunk;
                if (!read_data(record.offset, record.aligned_size, &chunk, error)) {
                    return false;
                }
                if (!write_bytes_data(new_offset, chunk, error)) {
                    return false;
                }
            }
        }

        if (!zero_data(new_cursor, bytes_used - new_cursor, error)) {
            return false;
        }
        if (!write_bytes_used(new_cursor, error)) {
            return false;
        }
        dirty_ = true;
        *changed = true;
        return true;
    }

    bool save(std::string* error) {
        if (!dirty_) {
            return true;
        }
        if (msync(map_, map_size_, MS_SYNC) != 0) {
            *error = "msync failed: " + std::string(std::strerror(errno));
            return false;
        }
        return true;
    }

private:
    static constexpr std::uint32_t kInvalidOffset = std::numeric_limits<std::uint32_t>::max();

    bool validate_header() {
        if (map_size_ < kPropAreaHeaderSize) {
            return false;
        }

        std::uint32_t magic = 0;
        std::uint32_t version = 0;
        std::uint32_t bytes_used = 0;
        if (!read_u32_abs(offsetof(RawPropAreaHeader, magic), &magic) ||
            !read_u32_abs(offsetof(RawPropAreaHeader, version), &version) ||
            !read_u32_abs(offsetof(RawPropAreaHeader, bytes_used), &bytes_used)) {
            return false;
        }

        if (magic != kPropAreaMagic || version != kPropAreaVersion) {
            return false;
        }

        const std::size_t data_size = map_size_ - kPropAreaHeaderSize;
        if (data_size > std::numeric_limits<std::uint32_t>::max()) {
            return false;
        }
        data_size_ = static_cast<std::uint32_t>(data_size);
        if (bytes_used < kTrieNodeHeaderSize || bytes_used > data_size_) {
            return false;
        }

        return true;
    }

    bool read_u32_abs(std::size_t absolute_offset, std::uint32_t* value) const {
        if (absolute_offset + sizeof(std::uint32_t) > map_size_) {
            return false;
        }
        std::memcpy(value, map_ + absolute_offset, sizeof(*value));
        return true;
    }

    bool get_bytes_used(std::uint32_t* bytes_used, std::string* error) const {
        if (!read_u32_abs(offsetof(RawPropAreaHeader, bytes_used), bytes_used)) {
            *error = "failed to read bytes_used";
            return false;
        }
        return true;
    }

    static std::uint32_t compose_initial_serial(std::uint32_t serial_len, bool is_long) {
        std::uint32_t serial = serial_len << 24;
        if (is_long) {
            serial |= kPropInfoLongFlag;
        }
        return serial;
    }

    static std::uint32_t compose_updated_serial(std::uint32_t old_serial, std::uint32_t serial_len,
                                                bool is_long) {
        std::uint32_t serial = serial_len << 24;
        if (is_long) {
            serial |= kPropInfoLongFlag;
        }
        const std::uint32_t counter = (((old_serial & 0x00ffffffu) | 1u) + 1u) & 0x00ffffffu;
        return serial | counter;
    }

    static std::uint32_t compose_visible_serial(std::uint32_t serial_dirty,
                                                std::uint32_t serial_len, bool is_long) {
        std::uint32_t serial = serial_len << 24;
        if (is_long) {
            serial |= kPropInfoLongFlag;
        }
        serial |= (serial_dirty + 1u) & 0x00ffffffu;
        return serial;
    }

    static std::uint32_t compose_hidden_serial(std::uint32_t serial_dirty, std::uint32_t serial_len,
                                               bool is_long) {
        std::uint32_t serial = serial_len << 24;
        if (is_long) {
            serial |= kPropInfoLongFlag;
        }
        serial |= (serial_dirty & ~1u) & 0x00ffffffu;
        return serial;
    }

    bool write_bytes_used(std::uint32_t bytes_used, std::string* error) {
        return write_u32_abs(offsetof(RawPropAreaHeader, bytes_used), bytes_used, error);
    }

    bool write_u32_abs(std::size_t absolute_offset, std::uint32_t value, std::string* error) {
        if (absolute_offset + sizeof(value) > map_size_) {
            *error = "absolute offset out of range";
            return false;
        }
        std::memcpy(map_ + absolute_offset, &value, sizeof(value));
        return true;
    }

    bool store_u32_abs_relaxed(std::size_t absolute_offset, std::uint32_t value,
                               std::string* error) {
        if (absolute_offset + sizeof(value) > map_size_) {
            *error = "absolute offset out of range";
            return false;
        }
        auto* ptr = reinterpret_cast<std::uint32_t*>(map_ + absolute_offset);
        __atomic_store_n(ptr, value, __ATOMIC_RELAXED);
        return true;
    }

    bool check_range(std::uint32_t data_offset, std::uint32_t len, std::size_t* absolute_offset,
                     std::string* error) const {
        const std::uint64_t end = static_cast<std::uint64_t>(data_offset) + len;
        if (end > data_size_) {
            *error = "data offset out of range";
            return false;
        }
        *absolute_offset = kPropAreaHeaderSize + static_cast<std::size_t>(data_offset);
        return true;
    }

    bool read_u32_data(std::uint32_t data_offset, std::uint32_t* value, std::string* error) const {
        std::size_t absolute_offset = 0;
        if (!check_range(data_offset, sizeof(*value), &absolute_offset, error)) {
            return false;
        }
        std::memcpy(value, map_ + absolute_offset, sizeof(*value));
        return true;
    }

    bool write_u32_data(std::uint32_t data_offset, std::uint32_t value, std::string* error) {
        std::size_t absolute_offset = 0;
        if (!check_range(data_offset, sizeof(value), &absolute_offset, error)) {
            return false;
        }
        std::memcpy(map_ + absolute_offset, &value, sizeof(value));
        return true;
    }

    bool store_u32_data_relaxed(std::uint32_t data_offset, std::uint32_t value,
                                std::string* error) {
        std::size_t absolute_offset = 0;
        if (!check_range(data_offset, sizeof(value), &absolute_offset, error)) {
            return false;
        }
        auto* ptr = reinterpret_cast<std::uint32_t*>(map_ + absolute_offset);
        __atomic_store_n(ptr, value, __ATOMIC_RELAXED);
        return true;
    }

    bool store_u32_data_release(std::uint32_t data_offset, std::uint32_t value,
                                std::string* error) {
        std::size_t absolute_offset = 0;
        if (!check_range(data_offset, sizeof(value), &absolute_offset, error)) {
            return false;
        }
        auto* ptr = reinterpret_cast<std::uint32_t*>(map_ + absolute_offset);
        __atomic_store_n(ptr, value, __ATOMIC_RELEASE);
        return true;
    }

    bool read_data(std::uint32_t data_offset, std::uint32_t len, std::vector<std::uint8_t>* out,
                   std::string* error) const {
        std::size_t absolute_offset = 0;
        if (!check_range(data_offset, len, &absolute_offset, error)) {
            return false;
        }
        out->assign(map_ + absolute_offset, map_ + absolute_offset + len);
        return true;
    }

    bool write_bytes_data(std::uint32_t data_offset, const std::vector<std::uint8_t>& bytes,
                          std::string* error) {
        std::size_t absolute_offset = 0;
        if (!check_range(data_offset, static_cast<std::uint32_t>(bytes.size()), &absolute_offset,
                         error)) {
            return false;
        }
        std::copy(bytes.begin(), bytes.end(), map_ + absolute_offset);
        return true;
    }

    bool write_bytes_data(std::uint32_t data_offset, const std::uint8_t* bytes, std::uint32_t len,
                          std::string* error) {
        std::size_t absolute_offset = 0;
        if (!check_range(data_offset, len, &absolute_offset, error)) {
            return false;
        }
        std::memcpy(map_ + absolute_offset, bytes, len);
        return true;
    }

    bool zero_data(std::uint32_t data_offset, std::uint32_t len, std::string* error) {
        std::size_t absolute_offset = 0;
        if (!check_range(data_offset, len, &absolute_offset, error)) {
            return false;
        }
        std::memset(map_ + absolute_offset, 0, len);
        return true;
    }

    bool read_c_string(std::uint32_t data_offset, std::optional<std::uint32_t> max_len,
                       std::string* out, std::string* error) const {
        std::vector<std::uint8_t> bytes;
        if (!read_c_string_bytes(data_offset, max_len, &bytes, error)) {
            return false;
        }
        out->assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        return true;
    }

    bool read_c_string_bytes(std::uint32_t data_offset, std::optional<std::uint32_t> max_len,
                             std::vector<std::uint8_t>* out, std::string* error) const {
        if (data_offset > data_size_) {
            *error = "string offset out of range";
            return false;
        }

        const std::uint32_t limit = max_len.has_value() ? *max_len : (data_size_ - data_offset);
        std::size_t absolute_offset = 0;
        if (!check_range(data_offset, limit, &absolute_offset, error)) {
            return false;
        }

        const std::uint8_t* begin = map_ + absolute_offset;
        const std::uint8_t* end = begin + limit;
        const std::uint8_t* nul = static_cast<const std::uint8_t*>(std::memchr(begin, 0, limit));
        if (nul == nullptr || nul > end) {
            *error = "unterminated c string";
            return false;
        }

        out->assign(begin, nul);
        return true;
    }

    bool read_node(std::uint32_t offset, TrieNodeRecord* node, std::string* error) const {
        std::size_t absolute_offset = 0;
        if (!check_range(offset, kTrieNodeHeaderSize, &absolute_offset, error)) {
            return false;
        }

        RawTrieNodeHeader raw{};
        std::memcpy(&raw, map_ + absolute_offset, sizeof(raw));

        node->offset = offset;
        node->namelen = raw.namelen;
        node->prop = raw.prop;
        node->left = raw.left;
        node->right = raw.right;
        node->children = raw.children;
        node->name.clear();
        if (raw.namelen != 0 &&
            !read_c_string(offset + kTrieNodeHeaderSize, raw.namelen + 1, &node->name, error)) {
            return false;
        }

        return true;
    }

    bool read_prop_record(std::uint32_t prop_offset, PropRecord* record, std::string* error) const {
        std::size_t absolute_offset = 0;
        if (!check_range(prop_offset, kPropInfoSize, &absolute_offset, error)) {
            return false;
        }

        RawPropInfoHeader raw{};
        std::memcpy(&raw, map_ + absolute_offset, sizeof(raw));

        if (!read_c_string(prop_offset + kPropInfoSize, std::nullopt, &record->name, error)) {
            return false;
        }

        record->prop_offset = prop_offset;
        record->is_long = (raw.serial & kPropInfoLongFlag) != 0;
        if (record->is_long) {
            std::uint32_t rel_offset = 0;
            std::memcpy(&rel_offset,
                        reinterpret_cast<const std::uint8_t*>(&raw) + kLongOffsetInInfo,
                        sizeof(rel_offset));
            const std::uint32_t min_rel = align_up(kPropInfoSize + record->name.size() + 1, 4);
            if (rel_offset < min_rel) {
                *error = "long property offset points into prop_info";
                return false;
            }
            record->value_offset = prop_offset + rel_offset;
            if (!read_c_string(record->value_offset, std::nullopt, &record->value, error)) {
                return false;
            }
        } else {
            const char* value = raw.value;
            const void* nul = std::memchr(value, 0, kPropValueMax);
            if (nul == nullptr) {
                *error = "inline property value is not null terminated";
                return false;
            }
            const std::size_t value_len = static_cast<const char*>(nul) - value;
            record->value.assign(value, value_len);
            record->value_offset = prop_offset + sizeof(raw.serial);
        }

        return true;
    }

    bool ensure_traverse_trie(const std::string& key, std::uint32_t* node_offset,
                              std::string* error) {
        if (key.empty()) {
            *error = "property key is empty";
            return false;
        }

        const auto segments = split_segments(key);
        if (std::any_of(segments.begin(), segments.end(),
                        [](const std::string& segment) { return segment.empty(); })) {
            *error = "property key contains empty segment";
            return false;
        }

        std::uint32_t current_offset = 0;
        for (const auto& segment : segments) {
            TrieNodeRecord current;
            if (!read_node(current_offset, &current, error)) {
                return false;
            }

            std::uint32_t child_root = current.children;
            if (child_root == 0) {
                if (!create_trie_node(segment, &child_root, error) ||
                    !write_u32_data(current.offset + kNodeChildrenOffset, child_root, error)) {
                    return false;
                }
            }

            if (!ensure_sibling(child_root, segment, &current_offset, error)) {
                return false;
            }
        }

        *node_offset = current_offset;
        return true;
    }

    bool traverse_trie(const std::string& key, std::uint32_t* node_offset,
                       std::string* error) const {
        if (key.empty()) {
            *error = "property key is empty";
            return false;
        }

        const auto segments = split_segments(key);
        if (std::any_of(segments.begin(), segments.end(),
                        [](const std::string& segment) { return segment.empty(); })) {
            *error = "property key contains empty segment";
            return false;
        }

        std::uint32_t current_offset = 0;
        for (const auto& segment : segments) {
            TrieNodeRecord current;
            if (!read_node(current_offset, &current, error)) {
                return false;
            }
            if (current.children == 0) {
                *node_offset = kInvalidOffset;
                return true;
            }

            std::uint32_t next_offset = 0;
            if (!find_sibling(current.children, segment, &next_offset, error)) {
                return false;
            }
            if (next_offset == kInvalidOffset) {
                *node_offset = kInvalidOffset;
                return true;
            }
            current_offset = next_offset;
        }

        *node_offset = current_offset;
        return true;
    }

    bool find_sibling(std::uint32_t root_offset, const std::string& target,
                      std::uint32_t* match_offset, std::string* error) const {
        std::uint32_t current_offset = root_offset;
        const std::size_t max_steps =
            std::max<std::size_t>(1, data_size_ / std::max<std::uint32_t>(1, kTrieNodeHeaderSize));
        for (std::size_t step = 0; step < max_steps; ++step) {
            TrieNodeRecord current;
            if (!read_node(current_offset, &current, error)) {
                return false;
            }
            const int cmp = cmp_prop_name(target, current.name);
            if (cmp == 0) {
                *match_offset = current_offset;
                return true;
            }
            if (cmp < 0) {
                if (current.left == 0) {
                    *match_offset = kInvalidOffset;
                    return true;
                }
                current_offset = current.left;
            } else {
                if (current.right == 0) {
                    *match_offset = kInvalidOffset;
                    return true;
                }
                current_offset = current.right;
            }
        }

        *error = "possible cycle in sibling tree";
        return false;
    }

    bool ensure_sibling(std::uint32_t root_offset, const std::string& target,
                        std::uint32_t* match_offset, std::string* error) {
        std::uint32_t current_offset = root_offset;
        const std::size_t max_steps =
            std::max<std::size_t>(1, data_size_ / std::max<std::uint32_t>(1, kTrieNodeHeaderSize));
        for (std::size_t step = 0; step < max_steps; ++step) {
            TrieNodeRecord current;
            if (!read_node(current_offset, &current, error)) {
                return false;
            }
            const int cmp = cmp_prop_name(target, current.name);
            if (cmp == 0) {
                *match_offset = current_offset;
                return true;
            }
            if (cmp < 0) {
                if (current.left != 0) {
                    current_offset = current.left;
                    continue;
                }
                std::uint32_t new_offset = 0;
                if (!create_trie_node(target, &new_offset, error) ||
                    !write_u32_data(current.offset + kNodeLeftOffset, new_offset, error)) {
                    return false;
                }
                *match_offset = new_offset;
                return true;
            }
            if (current.right != 0) {
                current_offset = current.right;
                continue;
            }
            std::uint32_t new_offset = 0;
            if (!create_trie_node(target, &new_offset, error) ||
                !write_u32_data(current.offset + kNodeRightOffset, new_offset, error)) {
                return false;
            }
            *match_offset = new_offset;
            return true;
        }

        *error = "possible cycle while inserting sibling node";
        return false;
    }

    bool create_trie_node(const std::string& name, std::uint32_t* node_offset, std::string* error) {
        const std::uint32_t name_len = static_cast<std::uint32_t>(name.size());
        const std::uint32_t node_size = kTrieNodeHeaderSize + name_len + 1;
        if (!allocate_obj(node_size, node_offset, error) ||
            !write_u32_data(*node_offset, name_len, error) ||
            !write_u32_data(*node_offset + kNodePropOffset, 0, error) ||
            !write_u32_data(*node_offset + kNodeLeftOffset, 0, error) ||
            !write_u32_data(*node_offset + kNodeRightOffset, 0, error) ||
            !write_u32_data(*node_offset + kNodeChildrenOffset, 0, error) ||
            !write_bytes_data(*node_offset + kTrieNodeHeaderSize,
                              reinterpret_cast<const std::uint8_t*>(name.data()), name_len,
                              error)) {
            return false;
        }
        const std::uint8_t nul = 0;
        return write_bytes_data(*node_offset + kTrieNodeHeaderSize + name_len, &nul, 1, error);
    }

    bool create_prop_info(const std::string& name, const std::string& value,
                          std::uint32_t* prop_offset, std::string* error) {
        const std::uint32_t name_len = static_cast<std::uint32_t>(name.size());
        if (!allocate_obj(kPropInfoSize + name_len + 1, prop_offset, error) ||
            !write_u32_data(*prop_offset, 0, error)) {
            return false;
        }

        const bool use_long = value.size() >= kPropValueMax;
        if (use_long) {
            if (!write_long_layout(*prop_offset, name_len, value, error)) {
                return false;
            }
        } else if (!write_inline_value(*prop_offset, value, error)) {
            return false;
        }

        if (!write_bytes_data(*prop_offset + kPropInfoSize,
                              reinterpret_cast<const std::uint8_t*>(name.data()), name_len,
                              error)) {
            return false;
        }
        const std::uint8_t nul = 0;
        return write_bytes_data(*prop_offset + kPropInfoSize + name_len, &nul, 1, error);
    }

    bool wipe_prop_info(std::uint32_t prop_offset, std::string* error) {
        PropRecord record;
        if (!read_prop_record(prop_offset, &record, error)) {
            return false;
        }

        if (record.is_long &&
            !zero_data(record.value_offset, static_cast<std::uint32_t>(record.value.size() + 1),
                       error)) {
            return false;
        }
        if (!zero_data(prop_offset + kPropInfoSize,
                       static_cast<std::uint32_t>(record.name.size() + 1), error) ||
            !zero_data(prop_offset, kPropInfoSize, error)) {
            return false;
        }
        return true;
    }

    bool write_inline_value(std::uint32_t prop_offset, const std::string& value,
                            std::string* error) {
        if (value.size() >= kPropValueMax) {
            *error = "inline property value too large";
            return false;
        }
        if (!zero_data(prop_offset + sizeof(std::uint32_t), kPropValueMax, error) ||
            !write_bytes_data(prop_offset + sizeof(std::uint32_t),
                              reinterpret_cast<const std::uint8_t*>(value.data()),
                              static_cast<std::uint32_t>(value.size()), error)) {
            return false;
        }
        const std::uint8_t nul = 0;
        return write_bytes_data(prop_offset + sizeof(std::uint32_t) + value.size(), &nul, 1, error);
    }

    bool write_long_layout(std::uint32_t prop_offset, std::uint32_t name_len,
                           const std::string& value, std::string* error) {
        std::uint32_t long_offset = 0;
        if (!allocate_obj(static_cast<std::uint32_t>(value.size() + 1), &long_offset, error)) {
            return false;
        }
        const std::uint32_t relative_offset = long_offset - prop_offset;
        const std::uint32_t min_rel = align_up(kPropInfoSize + name_len + 1, 4);
        if (relative_offset < min_rel) {
            *error = "invalid long value placement";
            return false;
        }

        if (!zero_data(prop_offset + sizeof(std::uint32_t), kPropValueMax, error) ||
            !write_bytes_data(prop_offset + sizeof(std::uint32_t),
                              reinterpret_cast<const std::uint8_t*>(kLongLegacyError),
                              static_cast<std::uint32_t>(std::strlen(kLongLegacyError)), error) ||
            !write_u32_data(prop_offset + kLongOffsetInInfo, relative_offset, error) ||
            !write_bytes_data(long_offset, reinterpret_cast<const std::uint8_t*>(value.data()),
                              static_cast<std::uint32_t>(value.size()), error)) {
            return false;
        }
        const std::uint8_t nul = 0;
        return write_bytes_data(long_offset + value.size(), &nul, 1, error);
    }

    bool update_inline_property(std::uint32_t prop_offset, const std::string& value,
                                std::string* error) {
        return write_inline_value(prop_offset, value, error);
    }

    bool update_long_property(std::uint32_t prop_offset, const PropRecord& record,
                              const std::string& value, std::string* error) {
        if (value.size() > record.value.size()) {
            *error = "long property value too large for in-place update";
            return false;
        }
        const std::uint32_t capacity = static_cast<std::uint32_t>(record.value.size() + 1);
        if (!zero_data(record.value_offset, capacity, error) ||
            !write_bytes_data(record.value_offset,
                              reinterpret_cast<const std::uint8_t*>(value.data()),
                              static_cast<std::uint32_t>(value.size()), error)) {
            return false;
        }
        const std::uint8_t nul = 0;
        return write_bytes_data(record.value_offset + value.size(), &nul, 1, error);
    }

    bool prune_trie(std::uint32_t offset, bool* pruned, std::string* error) {
        TrieNodeRecord node;
        if (!read_node(offset, &node, error)) {
            return false;
        }

        bool is_leaf = true;
        if (node.children != 0) {
            bool prune_child = false;
            if (!prune_trie(node.children, &prune_child, error)) {
                return false;
            }
            if (prune_child) {
                if (!write_u32_data(offset + kNodeChildrenOffset, 0, error)) {
                    return false;
                }
            } else {
                is_leaf = false;
            }
        }
        if (node.left != 0) {
            bool prune_left = false;
            if (!prune_trie(node.left, &prune_left, error)) {
                return false;
            }
            if (prune_left) {
                if (!write_u32_data(offset + kNodeLeftOffset, 0, error)) {
                    return false;
                }
            } else {
                is_leaf = false;
            }
        }
        if (node.right != 0) {
            bool prune_right = false;
            if (!prune_trie(node.right, &prune_right, error)) {
                return false;
            }
            if (prune_right) {
                if (!write_u32_data(offset + kNodeRightOffset, 0, error)) {
                    return false;
                }
            } else {
                is_leaf = false;
            }
        }

        std::uint32_t prop = 0;
        if (!read_u32_data(offset + kNodePropOffset, &prop, error)) {
            return false;
        }
        if (is_leaf && prop == 0) {
            if (node.namelen != 0 &&
                !zero_data(offset + kTrieNodeHeaderSize, node.namelen + 1, error)) {
                return false;
            }
            if (!zero_data(offset, kTrieNodeHeaderSize, error)) {
                return false;
            }
            *pruned = true;
            return true;
        }

        *pruned = false;
        return true;
    }

    bool has_dirty_backup(std::string* error) const {
        TrieNodeRecord root;
        if (!read_node(0, &root, error)) {
            return false;
        }

        if (root.children != 0 && root.children == kTrieNodeHeaderSize) {
            return false;
        }
        if (root.children == 0) {
            std::uint32_t bytes_used = 0;
            if (!get_bytes_used(&bytes_used, error)) {
                return false;
            }
            return bytes_used == kInitialBytesUsed;
        }
        return true;
    }

    bool allocate_obj(std::uint32_t size, std::uint32_t* offset, std::string* error) {
        std::uint32_t bytes_used = 0;
        if (!get_bytes_used(&bytes_used, error)) {
            return false;
        }
        const std::uint32_t aligned = align_up(size, 4);
        const std::uint64_t next = static_cast<std::uint64_t>(bytes_used) + aligned;
        if (next > data_size_) {
            *error = "prop area is full";
            return false;
        }
        if (!write_bytes_used(static_cast<std::uint32_t>(next), error) ||
            !zero_data(bytes_used, aligned, error)) {
            return false;
        }
        *offset = bytes_used;
        return true;
    }

    bool collect_compact_records_from(
        std::uint32_t offset, std::optional<std::uint32_t> referer_data,
        std::optional<std::uint32_t> refer_off, std::set<std::uint32_t>* seen_nodes,
        std::set<std::uint32_t>* seen_props, std::set<std::uint32_t>* seen_longs,
        std::vector<CompactRecord>* records, std::string* error) const {
        if (!seen_nodes->insert(offset).second) {
            return true;
        }

        TrieNodeRecord node;
        if (!read_node(offset, &node, error)) {
            return false;
        }

        const std::uint32_t node_size =
            node.namelen == 0 ? kTrieNodeHeaderSize : (kTrieNodeHeaderSize + node.namelen + 1);
        records->push_back(
            make_compact_record(offset, align_up(node_size, 4), referer_data, refer_off));

        if (node.prop != 0 && seen_props->insert(node.prop).second) {
            PropRecord record;
            if (!read_prop_record(node.prop, &record, error)) {
                return false;
            }
            records->push_back(
                make_compact_record(node.prop, align_up(kPropInfoSize + record.name.size() + 1, 4),
                                    offset, kNodePropOffset));
            if (record.is_long && seen_longs->insert(record.value_offset).second) {
                records->push_back(make_compact_record(record.value_offset,
                                                       align_up(record.value.size() + 1, 4),
                                                       node.prop, kLongOffsetInInfo, node.prop));
            }
        }

        if (node.left != 0 &&
            !collect_compact_records_from(node.left, offset, kNodeLeftOffset, seen_nodes,
                                          seen_props, seen_longs, records, error)) {
            return false;
        }
        if (node.children != 0 &&
            !collect_compact_records_from(node.children, offset, kNodeChildrenOffset, seen_nodes,
                                          seen_props, seen_longs, records, error)) {
            return false;
        }
        if (node.right != 0 &&
            !collect_compact_records_from(node.right, offset, kNodeRightOffset, seen_nodes,
                                          seen_props, seen_longs, records, error)) {
            return false;
        }

        return true;
    }

    std::string path_;
    int fd_ = -1;
    std::uint8_t* map_ = nullptr;
    std::size_t map_size_ = 0;
    std::uint32_t data_size_ = 0;
    bool valid_ = false;
    bool dirty_ = false;
};

template <typename Fn>
bool with_each_valid_prop_area(const std::string& property_dir, const Fn& fn,
                               CompactSummary* summary, std::string* error) {
    std::vector<std::string> files;
    if (!collect_prop_area_targets(property_dir, &files, error)) {
        return false;
    }

    for (const auto& path : files) {
        if (summary != nullptr) {
            ++summary->files_scanned;
        }

        PropAreaFile area;
        if (!area.load(path, error)) {
            return false;
        }
        if (!area.valid()) {
            continue;
        }
        if (summary != nullptr) {
            ++summary->valid_areas;
        }
        if (!fn(path, &area, error)) {
            return false;
        }
    }

    return true;
}

}  // namespace

bool set_property_in_file(const std::string& path, const std::string& name,
                          const std::string& value, std::string* error) {
    PropAreaFile area;
    if (!area.load(path, error)) {
        return false;
    }
    if (!area.valid()) {
        *error = "invalid prop-area file: " + path;
        return false;
    }
    bool created = false;
    if (!area.set_property(name, value, &created, error)) {
        return false;
    }
    return area.save(error);
}

bool delete_property_in_file(const std::string& path, const std::string& name, bool* deleted,
                             std::string* error) {
    PropAreaFile area;
    if (!area.load(path, error)) {
        return false;
    }
    if (!area.valid()) {
        *error = "invalid prop-area file: " + path;
        return false;
    }
    if (!area.delete_property(name, deleted, error)) {
        return false;
    }
    if (!*deleted) {
        return true;
    }
    return area.save(error);
}

bool delete_property_by_scanning(const std::string& property_dir, const std::string& name,
                                 bool* deleted, std::string* error) {
    *deleted = false;
    return with_each_valid_prop_area(
        property_dir,
        [&](const std::string&, PropAreaFile* area, std::string* inner_error) {
            if (*deleted) {
                return true;
            }
            bool found = false;
            if (!area->has_property(name, &found, inner_error)) {
                return false;
            }
            if (!found) {
                return true;
            }

            bool removed = false;
            if (!area->delete_property(name, &removed, inner_error)) {
                return false;
            }
            if (removed && !area->save(inner_error)) {
                return false;
            }
            *deleted = removed;
            return true;
        },
        nullptr, error);
}

bool bump_property_area_serial(const std::string& property_dir, std::string* error) {
    std::string path = property_dir;
    struct stat st{};
    if (lstat(property_dir.c_str(), &st) != 0) {
        *error = format_errno("failed to stat", property_dir);
        return false;
    }
    if (S_ISDIR(st.st_mode)) {
        path = property_dir + "/properties_serial";
    } else if (!S_ISREG(st.st_mode)) {
        *error = "unsupported prop-area serial root: " + property_dir;
        return false;
    }

    PropAreaFile area;
    if (!area.load(path, error)) {
        return false;
    }
    if (!area.valid()) {
        *error = "invalid prop-area file: " + path;
        return false;
    }
    if (!area.bump_area_serial(error)) {
        return false;
    }
    return area.save(error);
}

bool compact_property_areas(const std::string& property_dir,
                            const std::optional<std::string>& context, CompactSummary* summary,
                            std::string* error) {
    if (summary != nullptr) {
        *summary = CompactSummary{};
    }

    if (context.has_value()) {
        std::string path = property_dir;
        struct stat st{};
        if (lstat(property_dir.c_str(), &st) != 0) {
            *error = format_errno("failed to stat", property_dir);
            return false;
        }
        if (S_ISDIR(st.st_mode)) {
            path = property_dir + "/" + *context;
        } else if (!S_ISREG(st.st_mode)) {
            *error = "unsupported prop-area root: " + property_dir;
            return false;
        }
        if (summary != nullptr) {
            summary->files_scanned = 1;
        }
        PropAreaFile area;
        if (!area.load(path, error)) {
            return false;
        }
        if (!area.valid()) {
            *error = "invalid prop-area file: " + path;
            return false;
        }
        if (summary != nullptr) {
            summary->valid_areas = 1;
        }
        bool changed = false;
        if (!area.compact(&changed, error)) {
            return false;
        }
        if (changed) {
            if (!area.save(error)) {
                return false;
            }
            if (summary != nullptr) {
                summary->files_compacted = 1;
            }
        }
        return true;
    }

    return with_each_valid_prop_area(
        property_dir,
        [&](const std::string&, PropAreaFile* area, std::string* inner_error) {
            bool changed = false;
            if (!area->compact(&changed, inner_error)) {
                return false;
            }
            if (changed) {
                if (!area->save(inner_error)) {
                    return false;
                }
                if (summary != nullptr) {
                    ++summary->files_compacted;
                }
            }
            return true;
        },
        summary, error);
}

}  // namespace resetprop
