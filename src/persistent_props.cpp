#include "persistent_props.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace resetprop {

namespace {

constexpr const char* kPersistPropDir = "/data/property";
constexpr const char* kPersistPropFile = "/data/property/persistent_properties";

std::string format_errno(const std::string& prefix, const std::string& path) {
    return prefix + " " + path + ": " + std::strerror(errno);
}

bool file_exists(const char* path) {
    struct stat st {};
    return stat(path, &st) == 0;
}

// Bulk read into an already-open fd. Streams went through streambuf one
// character at a time and had no size hint.
bool read_fd_all(int fd, std::string* out) {
    struct stat status{};
    if (fstat(fd, &status) == 0 && S_ISREG(status.st_mode) && status.st_size > 0) {
        out->reserve(static_cast<std::size_t>(status.st_size));
    }
    char buffer[65536];
    for (;;) {
        const ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            out->append(buffer, static_cast<std::size_t>(count));
            continue;
        }
        if (count == 0) {
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        return false;
    }
}

bool read_file(const std::string& path, std::string* contents, std::string* error) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        *error = format_errno("failed to open", path);
        return false;
    }
    const bool ok = read_fd_all(fd, contents);
    close(fd);
    if (!ok) {
        *error = format_errno("failed to read", path);
        contents->clear();
    }
    return ok;
}

bool read_binary_file(const std::string& path, std::vector<std::uint8_t>* bytes, std::string* error) {
    std::string contents;
    if (!read_file(path, &contents, error)) {
        return false;
    }
    bytes->assign(contents.begin(), contents.end());
    return true;
}

bool write_atomic_file(const std::string& path,
                       const std::uint8_t* data,
                       std::size_t size,
                       std::string* error) {
    std::string tmp = path + ".XXXXXX";
    std::vector<char> tmp_buf(tmp.begin(), tmp.end());
    tmp_buf.push_back('\0');

    const int fd = mkstemp(tmp_buf.data());
    if (fd < 0) {
        *error = format_errno("mkstemp failed for", path);
        return false;
    }

    bool ok = true;
    std::size_t offset = 0;
    while (offset < size) {
        const ssize_t n = write(fd, data + offset, size - offset);
        if (n < 0) {
            *error = "write failed: " + std::string(std::strerror(errno));
            ok = false;
            break;
        }
        offset += static_cast<std::size_t>(n);
    }

    struct stat st {};
    if (ok && stat(path.c_str(), &st) == 0) {
        if (fchmod(fd, st.st_mode) != 0) {
            *error = "fchmod failed: " + std::string(std::strerror(errno));
            ok = false;
        } else if (fchown(fd, st.st_uid, st.st_gid) != 0) {
            *error = "fchown failed: " + std::string(std::strerror(errno));
            ok = false;
        }
    } else if (ok && fchmod(fd, 0600) != 0) {
        *error = "fchmod failed: " + std::string(std::strerror(errno));
        ok = false;
    }

    if (ok && fsync(fd) != 0) {
        *error = "fsync failed: " + std::string(std::strerror(errno));
        ok = false;
    }

    close(fd);

    const std::string tmp_path(tmp_buf.data());
    if (!ok) {
        unlink(tmp_path.c_str());
        return false;
    }

    if (rename(tmp_path.c_str(), path.c_str()) != 0) {
        *error = format_errno("rename failed for", path);
        unlink(tmp_path.c_str());
        return false;
    }

    return true;
}

bool write_atomic_file(const std::string& path, const std::string& contents, std::string* error) {
    return write_atomic_file(path,
                             reinterpret_cast<const std::uint8_t*>(contents.data()),
                             contents.size(),
                             error);
}

bool read_varint(const std::vector<std::uint8_t>& bytes,
                 std::size_t* pos,
                 std::uint64_t* value,
                 std::string* error) {
    std::uint64_t result = 0;
    int shift = 0;
    while (*pos < bytes.size() && shift < 64) {
        const std::uint8_t byte = bytes[*pos];
        ++(*pos);
        result |= static_cast<std::uint64_t>(byte & 0x7f) << shift;
        if ((byte & 0x80u) == 0) {
            *value = result;
            return true;
        }
        shift += 7;
    }
    *error = "invalid protobuf varint";
    return false;
}

bool read_length_delimited(const std::vector<std::uint8_t>& bytes,
                           std::size_t* pos,
                           std::string* value,
                           std::string* error) {
    std::uint64_t length = 0;
    if (!read_varint(bytes, pos, &length, error)) {
        return false;
    }
    if (*pos + length > bytes.size()) {
        *error = "protobuf length out of range";
        return false;
    }
    value->assign(reinterpret_cast<const char*>(bytes.data() + *pos),
                  static_cast<std::size_t>(length));
    *pos += static_cast<std::size_t>(length);
    return true;
}

bool skip_wire_value(const std::vector<std::uint8_t>& bytes,
                     std::size_t* pos,
                     std::uint64_t wire_type,
                     std::string* error) {
    switch (wire_type) {
    case 0: {
        std::uint64_t ignored = 0;
        return read_varint(bytes, pos, &ignored, error);
    }
    case 2: {
        std::uint64_t length = 0;
        if (!read_varint(bytes, pos, &length, error)) {
            return false;
        }
        if (*pos + length > bytes.size()) {
            *error = "protobuf length out of range";
            return false;
        }
        *pos += static_cast<std::size_t>(length);
        return true;
    }
    default:
        *error = "unsupported protobuf wire type";
        return false;
    }
}

void append_varint(std::vector<std::uint8_t>* bytes, std::uint64_t value) {
    while (value >= 0x80u) {
        bytes->push_back(static_cast<std::uint8_t>(value) | 0x80u);
        value >>= 7;
    }
    bytes->push_back(static_cast<std::uint8_t>(value));
}

void append_length_delimited(std::vector<std::uint8_t>* bytes, const std::string& value) {
    append_varint(bytes, value.size());
    bytes->insert(bytes->end(), value.begin(), value.end());
}

bool load_proto_properties(PersistentPropertyMap* properties, std::string* error) {
    std::vector<std::uint8_t> bytes;
    if (!read_binary_file(kPersistPropFile, &bytes, error)) {
        return false;
    }

    std::size_t pos = 0;
    while (pos < bytes.size()) {
        std::uint64_t tag = 0;
        if (!read_varint(bytes, &pos, &tag, error)) {
            return false;
        }
        const std::uint64_t field_number = tag >> 3;
        const std::uint64_t wire_type = tag & 0x7u;
        if (field_number != 1 || wire_type != 2) {
            if (!skip_wire_value(bytes, &pos, wire_type, error)) {
                return false;
            }
            continue;
        }

        std::string record_bytes;
        if (!read_length_delimited(bytes, &pos, &record_bytes, error)) {
            return false;
        }

        std::size_t record_pos = 0;
        std::string name;
        std::string value;
        const auto record_view = std::vector<std::uint8_t>(record_bytes.begin(), record_bytes.end());
        while (record_pos < record_view.size()) {
            std::uint64_t record_tag = 0;
            if (!read_varint(record_view, &record_pos, &record_tag, error)) {
                return false;
            }
            const std::uint64_t record_field = record_tag >> 3;
            const std::uint64_t record_wire = record_tag & 0x7u;
            if (record_wire != 2) {
                if (!skip_wire_value(record_view, &record_pos, record_wire, error)) {
                    return false;
                }
                continue;
            }

            std::string field_value;
            if (!read_length_delimited(record_view, &record_pos, &field_value, error)) {
                return false;
            }
            if (record_field == 1) {
                name = std::move(field_value);
            } else if (record_field == 2) {
                value = std::move(field_value);
            }
        }

        if (!name.empty()) {
            (*properties)[name] = value;
        }
    }

    return true;
}

bool save_proto_properties(const PersistentPropertyMap& properties, std::string* error) {
    std::vector<std::uint8_t> bytes;
    for (const auto& [name, value] : properties) {
        std::vector<std::uint8_t> record;
        append_varint(&record, (1u << 3u) | 2u);
        append_length_delimited(&record, name);
        append_varint(&record, (2u << 3u) | 2u);
        append_length_delimited(&record, value);

        append_varint(&bytes, (1u << 3u) | 2u);
        append_varint(&bytes, record.size());
        bytes.insert(bytes.end(), record.begin(), record.end());
    }
    return write_atomic_file(kPersistPropFile, bytes.data(), bytes.size(), error);
}

bool get_legacy_prop_path(const std::string& name, std::string* path, std::string* error) {
    if (name.empty()) {
        *error = "property name is empty";
        return false;
    }
    *path = std::string(kPersistPropDir) + "/" + name;
    return true;
}

bool list_legacy_properties(PersistentPropertyMap* properties, std::string* error) {
    DIR* dir = opendir(kPersistPropDir);
    if (dir == nullptr) {
        *error = format_errno("failed to open directory", kPersistPropDir);
        return false;
    }

    while (true) {
        errno = 0;
        dirent* entry = readdir(dir);
        if (entry == nullptr) {
            if (errno != 0) {
                *error = format_errno("failed to read directory", kPersistPropDir);
                closedir(dir);
                return false;
            }
            break;
        }

        const std::string name(entry->d_name);
        if (name == "." || name == ".." || name == "persistent_properties" || name[0] == '.') {
            continue;
        }

        std::string path = std::string(kPersistPropDir) + "/" + name;
        struct stat st {};
        if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }

        std::string value;
        if (!read_file(path, &value, error)) {
            closedir(dir);
            return false;
        }
        (*properties)[name] = value;
    }

    closedir(dir);
    return true;
}

bool load_persistent_properties(PersistentPropertyMap* properties, std::string* error) {
    properties->clear();
    if (file_exists(kPersistPropFile)) {
        return load_proto_properties(properties, error);
    }
    return list_legacy_properties(properties, error);
}

}  // namespace

bool get_persistent_property(const std::string& name,
                             std::string* value,
                             bool* found,
                             std::string* error) {
    PersistentPropertyMap properties;
    if (!load_persistent_properties(&properties, error)) {
        return false;
    }
    const auto it = properties.find(name);
    *found = it != properties.end();
    if (*found) {
        *value = it->second;
    }
    return true;
}

bool list_persistent_properties(PersistentPropertyMap* properties, std::string* error) {
    return load_persistent_properties(properties, error);
}

bool set_persistent_property(const std::string& name,
                             const std::string& value,
                             std::string* error) {
    if (file_exists(kPersistPropFile)) {
        PersistentPropertyMap properties;
        if (!load_persistent_properties(&properties, error)) {
            return false;
        }
        properties[name] = value;
        return save_proto_properties(properties, error);
    }

    std::string path;
    if (!get_legacy_prop_path(name, &path, error)) {
        return false;
    }
    return write_atomic_file(path, value, error);
}

bool delete_persistent_property(const std::string& name,
                                bool* deleted,
                                std::string* error) {
    *deleted = false;

    if (file_exists(kPersistPropFile)) {
        PersistentPropertyMap properties;
        if (!load_persistent_properties(&properties, error)) {
            return false;
        }
        const auto it = properties.find(name);
        if (it == properties.end()) {
            return true;
        }
        properties.erase(it);
        *deleted = true;
        return save_proto_properties(properties, error);
    }

    std::string path;
    if (!get_legacy_prop_path(name, &path, error)) {
        return false;
    }
    if (unlink(path.c_str()) == 0) {
        *deleted = true;
        return true;
    }
    if (errno == ENOENT) {
        return true;
    }
    *error = format_errno("unlink failed for", path);
    return false;
}

}  // namespace resetprop
