#include "property_contexts.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace resetprop {

namespace {

constexpr const char* kDefaultPropsRoot = "/dev/__properties__";
constexpr const char* kDefaultSystemRoot = "/";
constexpr const char* kDefaultPropertyContext = "u:object_r:default_prop:s0";
constexpr const char* kPreSplitPropertyContext = "u:object_r:properties_device:s0";
constexpr std::uint32_t kSupportedPropertyInfoVersion = 2;

std::string trim(std::string value) {
    auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

bool path_exists(const std::string& path, struct stat* st) {
    return stat(path.c_str(), st) == 0;
}

bool is_directory(const std::string& path) {
    struct stat st {};
    return path_exists(path, &st) && S_ISDIR(st.st_mode);
}

bool is_regular_file(const std::string& path) {
    struct stat st {};
    return path_exists(path, &st) && S_ISREG(st.st_mode);
}

bool read_file_bytes(const std::string& path, std::vector<std::uint8_t>* data, std::string* error) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        *error = "failed to open " + path;
        return false;
    }
    struct stat status{};
    if (fstat(fd, &status) != 0 || status.st_size < 0) {
        *error = "failed to stat " + path;
        close(fd);
        return false;
    }
    data->resize(static_cast<std::size_t>(status.st_size));
    std::size_t filled = 0;
    while (filled < data->size()) {
        const ssize_t count = read(fd, data->data() + filled, data->size() - filled);
        if (count > 0) {
            filled += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        *error = "failed to read " + path;
        close(fd);
        data->clear();
        return false;
    }
    close(fd);
    return true;
}

int compare_segment_prefix(const std::string& child, const std::string& piece) {
    const std::size_t n = piece.size();
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned char cb = i < child.size() ? static_cast<unsigned char>(child[i]) : 0;
        const unsigned char pb = static_cast<unsigned char>(piece[i]);
        if (cb < pb) {
            return -1;
        }
        if (cb > pb) {
            return 1;
        }
    }
    return child.size() > n ? 1 : 0;
}

class SerializedContext {
public:
    bool load(const std::string& path, std::string* error) {
        if (!read_file_bytes(path, &data_, error)) {
            return false;
        }
        if (data_.size() < 24) {
            *error = "property_info file too small";
            return false;
        }

        std::uint32_t minimum_version = 0;
        if (!read_u32(4, &minimum_version) || minimum_version > kSupportedPropertyInfoVersion) {
            *error = "unsupported property_info version";
            return false;
        }

        if (!parse_context_table(error) || !parse_root_offset(error)) {
            return false;
        }
        return true;
    }

    std::string get_context_for_name(const std::string& name) const {
        std::uint32_t context_index = std::numeric_limits<std::uint32_t>::max();
        if (!get_context_index(name, &context_index) ||
            context_index == std::numeric_limits<std::uint32_t>::max() ||
            context_index >= contexts_.size()) {
            return kDefaultPropertyContext;
        }
        return contexts_[context_index];
    }

    std::vector<std::string> list_all_contexts() const { return contexts_; }

private:
    struct PropertyEntry {
        std::string name;
        std::uint32_t context_index = std::numeric_limits<std::uint32_t>::max();
    };

    bool read_u32(std::size_t offset, std::uint32_t* value) const {
        if (offset + sizeof(*value) > data_.size()) {
            return false;
        }
        std::memcpy(value, data_.data() + offset, sizeof(*value));
        return true;
    }

    bool read_cstring(std::size_t offset, std::string* value) const {
        if (offset >= data_.size()) {
            return false;
        }
        const auto* begin = reinterpret_cast<const char*>(data_.data() + offset);
        const auto* end = reinterpret_cast<const char*>(data_.data() + data_.size());
        const auto* nul = std::find(begin, end, '\0');
        if (nul == end) {
            return false;
        }
        *value = std::string(begin, nul);
        return true;
    }

    bool parse_context_table(std::string* error) {
        std::uint32_t contexts_offset = 0;
        if (!read_u32(12, &contexts_offset) || contexts_offset >= data_.size()) {
            *error = "invalid property_info contexts table";
            return false;
        }
        std::uint32_t count = 0;
        if (!read_u32(contexts_offset, &count)) {
            *error = "invalid property_info context count";
            return false;
        }
        contexts_.clear();
        contexts_.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            std::uint32_t string_offset = 0;
            if (!read_u32(contexts_offset + 4 + i * 4, &string_offset)) {
                *error = "invalid property_info context entry";
                return false;
            }
            std::string context;
            if (!read_cstring(string_offset, &context)) {
                *error = "invalid property_info context string";
                return false;
            }
            contexts_.push_back(std::move(context));
        }
        return true;
    }

    bool parse_root_offset(std::string* error) {
        std::uint32_t root_offset = 0;
        if (!read_u32(20, &root_offset) || root_offset + 28 > data_.size()) {
            *error = "invalid property_info root offset";
            return false;
        }
        root_offset_ = root_offset;
        return true;
    }

    bool node_property_entry_offset(std::size_t node_offset, std::uint32_t* entry_offset) const {
        return read_u32(node_offset, entry_offset);
    }

    bool node_context_index(std::size_t node_offset, std::uint32_t* context_index) const {
        std::uint32_t entry_offset = 0;
        if (!node_property_entry_offset(node_offset, &entry_offset)) {
            return false;
        }
        return read_u32(entry_offset + 8, context_index);
    }

    bool node_num_children(std::size_t node_offset, std::uint32_t* count) const {
        return read_u32(node_offset + 4, count);
    }

    bool node_child_array_offset(std::size_t node_offset, std::uint32_t* array_offset) const {
        return read_u32(node_offset + 8, array_offset);
    }

    bool node_num_prefixes(std::size_t node_offset, std::uint32_t* count) const {
        return read_u32(node_offset + 12, count);
    }

    bool node_prefix_array_offset(std::size_t node_offset, std::uint32_t* array_offset) const {
        return read_u32(node_offset + 16, array_offset);
    }

    bool node_num_exact_matches(std::size_t node_offset, std::uint32_t* count) const {
        return read_u32(node_offset + 20, count);
    }

    bool node_exact_array_offset(std::size_t node_offset, std::uint32_t* array_offset) const {
        return read_u32(node_offset + 24, array_offset);
    }

    bool read_property_entry(std::uint32_t entry_offset, PropertyEntry* entry) const {
        std::uint32_t name_offset = 0;
        if (!read_u32(entry_offset, &name_offset) ||
            !read_u32(entry_offset + 8, &entry->context_index) ||
            !read_cstring(name_offset, &entry->name)) {
            return false;
        }
        return true;
    }

    void check_prefix_match(const std::string& remaining,
                            std::size_t node_offset,
                            std::uint32_t* context_index) const {
        std::uint32_t count = 0;
        std::uint32_t array_offset = 0;
        if (!node_num_prefixes(node_offset, &count) ||
            !node_prefix_array_offset(node_offset, &array_offset)) {
            return;
        }
        for (std::uint32_t i = 0; i < count; ++i) {
            std::uint32_t entry_offset = 0;
            if (!read_u32(array_offset + i * 4, &entry_offset)) {
                return;
            }
            PropertyEntry entry;
            if (!read_property_entry(entry_offset, &entry)) {
                return;
            }
            if (entry.name.size() > remaining.size()) {
                continue;
            }
            if (remaining.compare(0, entry.name.size(), entry.name) == 0 &&
                entry.context_index != std::numeric_limits<std::uint32_t>::max()) {
                *context_index = entry.context_index;
                return;
            }
        }
    }

    bool find_child(std::size_t node_offset, const std::string& piece, std::size_t* child_offset) const {
        std::uint32_t count = 0;
        std::uint32_t array_offset = 0;
        if (!node_num_children(node_offset, &count) ||
            !node_child_array_offset(node_offset, &array_offset)) {
            return false;
        }
        if (count == 0) {
            return false;
        }

        std::int32_t low = 0;
        std::int32_t high = static_cast<std::int32_t>(count) - 1;
        while (low <= high) {
            const std::int32_t mid = (low + high) / 2;
            std::uint32_t child_entry = 0;
            if (!read_u32(array_offset + static_cast<std::size_t>(mid) * 4, &child_entry)) {
                return false;
            }
            std::uint32_t prop_entry_offset = 0;
            if (!node_property_entry_offset(child_entry, &prop_entry_offset)) {
                return false;
            }
            PropertyEntry entry;
            if (!read_property_entry(prop_entry_offset, &entry)) {
                return false;
            }
            const int cmp = compare_segment_prefix(entry.name, piece);
            if (cmp == 0) {
                *child_offset = child_entry;
                return true;
            }
            if (cmp < 0) {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
        return false;
    }

    bool get_context_index(const std::string& name, std::uint32_t* context_index) const {
        std::size_t node_offset = root_offset_;
        std::string remaining = name;

        while (true) {
            std::uint32_t node_context = std::numeric_limits<std::uint32_t>::max();
            if (node_context_index(node_offset, &node_context) &&
                node_context != std::numeric_limits<std::uint32_t>::max()) {
                *context_index = node_context;
            }

            check_prefix_match(remaining, node_offset, context_index);

            const auto dot = remaining.find('.');
            if (dot == std::string::npos) {
                break;
            }

            std::size_t child_offset = 0;
            if (!find_child(node_offset, remaining.substr(0, dot), &child_offset)) {
                break;
            }
            node_offset = child_offset;
            remaining.erase(0, dot + 1);
        }

        std::uint32_t exact_count = 0;
        std::uint32_t exact_array_offset = 0;
        if (node_num_exact_matches(node_offset, &exact_count) &&
            node_exact_array_offset(node_offset, &exact_array_offset)) {
            for (std::uint32_t i = 0; i < exact_count; ++i) {
                std::uint32_t entry_offset = 0;
                if (!read_u32(exact_array_offset + i * 4, &entry_offset)) {
                    break;
                }
                PropertyEntry entry;
                if (!read_property_entry(entry_offset, &entry)) {
                    break;
                }
                if (entry.name == remaining) {
                    if (entry.context_index != std::numeric_limits<std::uint32_t>::max()) {
                        *context_index = entry.context_index;
                    }
                    return true;
                }
            }
        }

        check_prefix_match(remaining, node_offset, context_index);
        return true;
    }

    std::vector<std::uint8_t> data_;
    std::vector<std::string> contexts_;
    std::size_t root_offset_ = 0;
};

class SplitContext {
public:
    bool load(const std::string& system_root, std::string* error) {
        entries_.clear();

        const std::string legacy = system_root + "/property_contexts";
        if (is_regular_file(legacy)) {
            return load_file(legacy, error);
        }

        const char* const modern_paths[] = {
            "/system/etc/selinux/plat_property_contexts",
            "/system_ext/etc/selinux/system_ext_property_contexts",
            "/product/etc/selinux/product_property_contexts",
            "/vendor/etc/selinux/vendor_property_contexts",
            "/odm/etc/selinux/odm_property_contexts",
            "/vendor/etc/selinux/nonplat_property_contexts",
        };

        bool loaded_any = false;
        for (const char* suffix : modern_paths) {
            const std::string path = system_root + suffix;
            if (!is_regular_file(path)) {
                continue;
            }
            if (!load_file(path, error)) {
                return false;
            }
            loaded_any = true;
        }

        if (!loaded_any) {
            *error = "no property_contexts file found under " + system_root;
            return false;
        }
        return true;
    }

    std::string get_context_for_name(const std::string& name) const {
        const Entry* best_exact = nullptr;
        const Entry* best_prefix = nullptr;
        const Entry* wildcard = nullptr;

        for (const auto& entry : entries_) {
            if (entry.pattern == "*") {
                if (wildcard == nullptr) {
                    wildcard = &entry;
                }
                continue;
            }
            if (entry.exact) {
                if (entry.pattern == name &&
                    (best_exact == nullptr || entry.pattern.size() > best_exact->pattern.size())) {
                    best_exact = &entry;
                }
                continue;
            }
            if (name.rfind(entry.pattern, 0) == 0 &&
                (best_prefix == nullptr || entry.pattern.size() > best_prefix->pattern.size())) {
                best_prefix = &entry;
            }
        }

        if (best_exact != nullptr) {
            return best_exact->context;
        }
        if (best_prefix != nullptr) {
            return best_prefix->context;
        }
        if (wildcard != nullptr) {
            return wildcard->context;
        }
        return kDefaultPropertyContext;
    }

    std::vector<std::string> list_all_contexts() const {
        std::vector<std::string> contexts;
        for (const auto& entry : entries_) {
            if (std::find(contexts.begin(), contexts.end(), entry.context) == contexts.end()) {
                contexts.push_back(entry.context);
            }
        }
        return contexts;
    }

private:
    struct Entry {
        std::string pattern;
        std::string context;
        bool exact = false;
    };

    bool load_file(const std::string& path, std::string* error) {
        std::vector<std::uint8_t> bytes;
        if (!read_file_bytes(path, &bytes, error)) {
            return false;
        }

        const std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        std::size_t begin = 0;
        while (begin < text.size()) {
            std::size_t end = text.find('\n', begin);
            const bool last = (end == std::string_view::npos);
            if (last) {
                end = text.size();
            }
            std::string line(text.substr(begin, end - begin));
            begin = last ? text.size() : end + 1;

            const auto comment_pos = line.find('#');
            if (comment_pos != std::string::npos) {
                line.erase(comment_pos);
            }
            line = trim(std::move(line));
            if (line.empty()) {
                continue;
            }

            constexpr std::string_view kWhitespace = " \t\r\f\v";
            std::vector<std::string> fields;
            for (std::size_t cursor = 0; cursor < line.size();) {
                cursor = line.find_first_not_of(kWhitespace, cursor);
                if (cursor == std::string::npos) {
                    break;
                }
                std::size_t field_end = line.find_first_of(kWhitespace, cursor);
                if (field_end == std::string::npos) {
                    field_end = line.size();
                }
                fields.emplace_back(line, cursor, field_end - cursor);
                cursor = field_end;
            }
            if (fields.size() < 2 || fields[0].rfind("ctl.", 0) == 0) {
                continue;
            }

            Entry entry;
            entry.pattern = std::move(fields[0]);
            entry.context = std::move(fields[1]);
            entry.exact = fields.size() >= 3 && fields[2] == "exact";
            entries_.push_back(std::move(entry));
        }

        return true;
    }

    std::vector<Entry> entries_;
};

class PropertyContextResolver {
public:
    bool load(const std::string& props_root, const std::string& system_root, std::string* error) {
        props_root_ = props_root;
        system_root_ = system_root;

        if (is_regular_file(props_root_)) {
            type_ = PropertyContextType::PreSplit;
            return true;
        }
        if (!is_directory(props_root_)) {
            *error = "invalid property root: " + props_root_;
            return false;
        }

        const std::string property_info = props_root_ + "/property_info";
        if (is_regular_file(property_info)) {
            auto serialized = std::make_unique<SerializedContext>();
            if (!serialized->load(property_info, error)) {
                return false;
            }
            serialized_ = std::move(serialized);
            type_ = PropertyContextType::Serialized;
            return true;
        }

        auto split = std::make_unique<SplitContext>();
        if (!split->load(system_root_, error)) {
            return false;
        }
        split_ = std::move(split);
        type_ = PropertyContextType::Split;
        return true;
    }

    PropertyContextType type() const { return type_; }

    std::string get_context_for_name(const std::string& name) const {
        switch (type_) {
            case PropertyContextType::Serialized:
                return serialized_ != nullptr ? serialized_->get_context_for_name(name)
                                              : std::string(kDefaultPropertyContext);
            case PropertyContextType::Split:
                return split_ != nullptr ? split_->get_context_for_name(name)
                                         : std::string(kDefaultPropertyContext);
            case PropertyContextType::PreSplit:
                return kPreSplitPropertyContext;
        }
        return kDefaultPropertyContext;
    }

    std::string context_file_path(const std::string& context) const {
        if (type_ == PropertyContextType::PreSplit) {
            return props_root_;
        }
        return props_root_ + "/" + context;
    }

    std::string serial_prop_area_path() const {
        if (type_ == PropertyContextType::PreSplit) {
            return props_root_;
        }
        return props_root_ + "/properties_serial";
    }

private:
    std::string props_root_;
    std::string system_root_;
    PropertyContextType type_ = PropertyContextType::Split;
    std::unique_ptr<SerializedContext> serialized_;
    std::unique_ptr<SplitContext> split_;
};

bool load_resolver(const std::string& props_root,
                   const std::string& system_root,
                   std::unordered_map<std::string, std::unique_ptr<PropertyContextResolver>>* cache,
                   PropertyContextResolver** resolver,
                   std::string* error) {
    auto it = cache->find(props_root);
    if (it != cache->end()) {
        *resolver = it->second.get();
        return true;
    }

    auto instance = std::make_unique<PropertyContextResolver>();
    if (!instance->load(props_root, system_root, error)) {
        return false;
    }
    auto* raw = instance.get();
    (*cache)[props_root] = std::move(instance);
    *resolver = raw;
    return true;
}

PropertyContextResolver* get_cached_resolver(const std::string& props_root, std::string* error) {
    static std::unordered_map<std::string, std::unique_ptr<PropertyContextResolver>> cache;
    PropertyContextResolver* resolver = nullptr;
    if (!load_resolver(props_root, kDefaultSystemRoot, &cache, &resolver, error)) {
        return nullptr;
    }
    return resolver;
}

}  // namespace

const char* property_context_type_name(PropertyContextType type) {
    switch (type) {
        case PropertyContextType::Serialized:
            return "serialized";
        case PropertyContextType::Split:
            return "split";
        case PropertyContextType::PreSplit:
            return "presplit";
    }
    return "unknown";
}

bool detect_property_context_type(const std::string& props_root,
                                  PropertyContextType* type,
                                  std::string* error) {
    auto* resolver = get_cached_resolver(props_root, error);
    if (resolver == nullptr) {
        return false;
    }
    *type = resolver->type();
    return true;
}

bool resolve_property_context(const std::string& name,
                              std::string* context,
                              std::string* error) {
    return resolve_property_context_from(kDefaultPropsRoot, name, context, error);
}

bool resolve_property_context_from(const std::string& props_root,
                                   const std::string& name,
                                   std::string* context,
                                   std::string* error) {
    auto* resolver = get_cached_resolver(props_root, error);
    if (resolver == nullptr) {
        return false;
    }
    *context = resolver->get_context_for_name(name);
    return true;
}

bool resolve_property_area_path(const std::string& props_root,
                                const std::string& name,
                                std::string* path,
                                std::string* context,
                                std::string* error) {
    auto* resolver = get_cached_resolver(props_root, error);
    if (resolver == nullptr) {
        return false;
    }
    *context = resolver->get_context_for_name(name);
    *path = resolver->context_file_path(*context);
    return true;
}

bool resolve_property_serial_path(const std::string& props_root,
                                  std::string* path,
                                  std::string* error) {
    auto* resolver = get_cached_resolver(props_root, error);
    if (resolver == nullptr) {
        return false;
    }
    *path = resolver->serial_prop_area_path();
    return true;
}

}  // namespace resetprop
