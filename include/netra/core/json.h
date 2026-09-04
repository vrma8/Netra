// SPDX-License-Identifier: MIT
// core/json.h : dependency-free JSON value model, writer and parser.
//
// Objects keep insertion order (std::vector of pairs) so generated reports are
// stable and human-readable.
#pragma once

#include <cstdint>
#include <initializer_list>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "netra/core/status.h"

namespace netra::json {

class Value;
using Array = std::vector<Value>;
using Object = std::vector<std::pair<std::string, Value>>;

enum class Type { kNull, kBool, kNumber, kString, kArray, kObject };

class Value {
public:
    Value() = default;
    Value(std::nullptr_t) {}  // NOLINT
    Value(bool b) : type_(Type::kBool), bool_(b) {}
    Value(int v) : type_(Type::kNumber), number_(v) {}
    Value(long v) : type_(Type::kNumber), number_(static_cast<double>(v)) {}
    Value(long long v) : type_(Type::kNumber), number_(static_cast<double>(v)) {}
    Value(unsigned v) : type_(Type::kNumber), number_(v) {}
    Value(unsigned long v) : type_(Type::kNumber), number_(static_cast<double>(v)) {}
    Value(unsigned long long v) : type_(Type::kNumber), number_(static_cast<double>(v)) {}
    Value(double v) : type_(Type::kNumber), number_(v) {}
    Value(const char* s) : type_(Type::kString), string_(s ? s : "") {}
    Value(std::string s) : type_(Type::kString), string_(std::move(s)) {}
    Value(std::string_view s) : type_(Type::kString), string_(s) {}
    Value(Array a) : type_(Type::kArray), array_(std::make_shared<Array>(std::move(a))) {}
    Value(Object o) : type_(Type::kObject), object_(std::make_shared<Object>(std::move(o))) {}

    static Value obj() { return Value(Object{}); }
    static Value arr() { return Value(Array{}); }
    static Value null() { return Value(); }

    Type type() const { return type_; }
    bool isNull() const { return type_ == Type::kNull; }
    bool isBool() const { return type_ == Type::kBool; }
    bool isNumber() const { return type_ == Type::kNumber; }
    bool isString() const { return type_ == Type::kString; }
    bool isArray() const { return type_ == Type::kArray; }
    bool isObject() const { return type_ == Type::kObject; }

    bool asBool(bool fallback = false) const { return isBool() ? bool_ : fallback; }
    double asNumber(double fallback = 0.0) const { return isNumber() ? number_ : fallback; }
    int64_t asInt(int64_t fallback = 0) const { return isNumber() ? static_cast<int64_t>(number_) : fallback; }
    std::string asString(std::string fallback = {}) const { return isString() ? string_ : std::move(fallback); }

    // ---- object accessors
    Value& operator[](const std::string& key);
    const Value* find(const std::string& key) const;
    bool contains(const std::string& key) const { return find(key) != nullptr; }
    void set(const std::string& key, Value value);
    void remove(const std::string& key);
    const Object& object() const;
    Object& object();
    size_t size() const;

    // ---- array accessors
    void push(Value value);
    const Array& array() const;
    Array& array();
    const Value& at(size_t index) const;

    std::string dump(bool pretty = false, int indent = 2) const;

private:
    void dumpTo(std::string& out, bool pretty, int indent, int depth) const;

    Type type_{Type::kNull};
    bool bool_{false};
    double number_{0.0};
    std::string string_;
    std::shared_ptr<Array> array_;
    std::shared_ptr<Object> object_;
};

/// Escapes a string for JSON output.
std::string escape(std::string_view text);

/// Serialise any Value to text.
std::string dump(const Value& value, bool pretty = false, int indent = 2);

/// Parse JSON text.
Result<Value> parse(std::string_view text);

}  // namespace netra::json
