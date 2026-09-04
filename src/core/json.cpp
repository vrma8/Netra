// SPDX-License-Identifier: MIT
#include "netra/core/json.h"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace netra::json {
namespace {

const Value kNull;

void appendNumber(std::string& out, double value) {
    if (std::isnan(value) || std::isinf(value)) {
        out += "null";
        return;
    }
    // Print integers without a decimal point.
    if (value == std::floor(value) && std::fabs(value) < 1e15) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(value));
        out += buf;
    } else {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "%.10g", value);
        out += buf;
    }
}

void appendIndent(std::string& out, bool pretty, int indent, int depth) {
    if (!pretty) return;
    out.push_back('\n');
    out.append(static_cast<size_t>(indent * depth), ' ');
}

class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) {}

    Result<Value> parseDocument() {
        skipWhitespace();
        auto value = parseValue();
        if (!value) return value.status();
        skipWhitespace();
        if (pos_ != text_.size()) return Status::invalidArgument(errorAt("unexpected trailing characters"));
        return *value;
    }

private:
    std::string errorAt(const std::string& message) const {
        size_t line = 1;
        size_t col = 1;
        for (size_t i = 0; i < pos_ && i < text_.size(); ++i) {
            if (text_[i] == '\n') {
                ++line;
                col = 1;
            } else {
                ++col;
            }
        }
        std::ostringstream os;
        os << "JSON parse error at line " << line << " column " << col << ": " << message;
        return os.str();
    }

    bool eof() const { return pos_ >= text_.size(); }
    char peek() const { return eof() ? '\0' : text_[pos_]; }
    char get() { return eof() ? '\0' : text_[pos_++]; }

    void skipWhitespace() {
        while (!eof()) {
            const char c = text_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++pos_;
            else break;
        }
    }

    Result<Value> parseValue() {
        if (depth_ > 200) return Status::invalidArgument(errorAt("nesting too deep"));
        skipWhitespace();
        if (eof()) return Status::invalidArgument(errorAt("unexpected end of input"));
        switch (peek()) {
            case '{': return parseObject();
            case '[': return parseArray();
            case '"': {
                auto s = parseString();
                if (!s) return s.status();
                return Value(*s);
            }
            case 't':
                if (text_.compare(pos_, 4, "true") == 0) {
                    pos_ += 4;
                    return Value(true);
                }
                return Status::invalidArgument(errorAt("invalid literal"));
            case 'f':
                if (text_.compare(pos_, 5, "false") == 0) {
                    pos_ += 5;
                    return Value(false);
                }
                return Status::invalidArgument(errorAt("invalid literal"));
            case 'n':
                if (text_.compare(pos_, 4, "null") == 0) {
                    pos_ += 4;
                    return Value(nullptr);
                }
                return Status::invalidArgument(errorAt("invalid literal"));
            default: return parseNumber();
        }
    }

    Result<Value> parseObject() {
        ++depth_;
        get();  // '{'
        Object obj;
        skipWhitespace();
        if (peek() == '}') {
            get();
            --depth_;
            return Value(std::move(obj));
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') return Status::invalidArgument(errorAt("expected object key"));
            auto key = parseString();
            if (!key) return key.status();
            skipWhitespace();
            if (get() != ':') return Status::invalidArgument(errorAt("expected ':'"));
            auto value = parseValue();
            if (!value) return value.status();
            obj.emplace_back(std::move(*key), std::move(*value));
            skipWhitespace();
            const char c = get();
            if (c == ',') continue;
            if (c == '}') break;
            return Status::invalidArgument(errorAt("expected ',' or '}'"));
        }
        --depth_;
        return Value(std::move(obj));
    }

    Result<Value> parseArray() {
        ++depth_;
        get();  // '['
        Array arr;
        skipWhitespace();
        if (peek() == ']') {
            get();
            --depth_;
            return Value(std::move(arr));
        }
        while (true) {
            auto value = parseValue();
            if (!value) return value.status();
            arr.push_back(std::move(*value));
            skipWhitespace();
            const char c = get();
            if (c == ',') continue;
            if (c == ']') break;
            return Status::invalidArgument(errorAt("expected ',' or ']'"));
        }
        --depth_;
        return Value(std::move(arr));
    }

    Result<std::string> parseString() {
        get();  // opening quote
        std::string out;
        while (true) {
            if (eof()) return Status::invalidArgument(errorAt("unterminated string"));
            const char c = get();
            if (c == '"') break;
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (eof()) return Status::invalidArgument(errorAt("unterminated escape"));
            const char esc = get();
            switch (esc) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    if (pos_ + 4 > text_.size()) return Status::invalidArgument(errorAt("bad \\u escape"));
                    unsigned code = 0;
                    for (int i = 0; i < 4; ++i) {
                        const char h = text_[pos_++];
                        code <<= 4;
                        if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
                        else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
                        else return Status::invalidArgument(errorAt("bad \\u escape"));
                    }
                    // Handle surrogate pairs.
                    if (code >= 0xD800 && code <= 0xDBFF && pos_ + 6 <= text_.size() && text_[pos_] == '\\' &&
                        text_[pos_ + 1] == 'u') {
                        unsigned low = 0;
                        size_t save = pos_;
                        pos_ += 2;
                        for (int i = 0; i < 4; ++i) {
                            const char h = text_[pos_++];
                            low <<= 4;
                            if (h >= '0' && h <= '9') low |= static_cast<unsigned>(h - '0');
                            else if (h >= 'a' && h <= 'f') low |= static_cast<unsigned>(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') low |= static_cast<unsigned>(h - 'A' + 10);
                            else {
                                pos_ = save;
                                low = 0;
                                break;
                            }
                        }
                        if (low >= 0xDC00 && low <= 0xDFFF) {
                            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                        } else {
                            pos_ = save;
                        }
                    }
                    if (code < 0x80) {
                        out.push_back(static_cast<char>(code));
                    } else if (code < 0x800) {
                        out.push_back(static_cast<char>(0xC0 | (code >> 6)));
                        out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    } else if (code < 0x10000) {
                        out.push_back(static_cast<char>(0xE0 | (code >> 12)));
                        out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                        out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    } else {
                        out.push_back(static_cast<char>(0xF0 | (code >> 18)));
                        out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
                        out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                        out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    }
                    break;
                }
                default: return Status::invalidArgument(errorAt("unknown escape sequence"));
            }
        }
        return out;
    }

    Result<Value> parseNumber() {
        const size_t start = pos_;
        if (peek() == '-' || peek() == '+') ++pos_;
        bool digits = false;
        while (!eof() && std::isdigit(static_cast<unsigned char>(peek()))) {
            ++pos_;
            digits = true;
        }
        if (peek() == '.') {
            ++pos_;
            while (!eof() && std::isdigit(static_cast<unsigned char>(peek()))) {
                ++pos_;
                digits = true;
            }
        }
        if (!digits) return Status::invalidArgument(errorAt("invalid number"));
        if (peek() == 'e' || peek() == 'E') {
            ++pos_;
            if (peek() == '+' || peek() == '-') ++pos_;
            while (!eof() && std::isdigit(static_cast<unsigned char>(peek()))) ++pos_;
        }
        const std::string token(text_.substr(start, pos_ - start));
        return Value(std::strtod(token.c_str(), nullptr));
    }

    std::string_view text_;
    size_t pos_{0};
    int depth_{0};
};

}  // namespace

Value& Value::operator[](const std::string& key) {
    if (type_ != Type::kObject) {
        type_ = Type::kObject;
        object_ = std::make_shared<Object>();
    }
    if (!object_) object_ = std::make_shared<Object>();
    for (auto& entry : *object_) {
        if (entry.first == key) return entry.second;
    }
    object_->emplace_back(key, Value());
    return object_->back().second;
}

const Value* Value::find(const std::string& key) const {
    if (!object_) return nullptr;
    for (const auto& entry : *object_) {
        if (entry.first == key) return &entry.second;
    }
    return nullptr;
}

void Value::set(const std::string& key, Value value) { (*this)[key] = std::move(value); }

void Value::remove(const std::string& key) {
    if (!object_) return;
    for (auto it = object_->begin(); it != object_->end(); ++it) {
        if (it->first == key) {
            object_->erase(it);
            return;
        }
    }
}

const Object& Value::object() const {
    static const Object kEmpty;
    return object_ ? *object_ : kEmpty;
}

Object& Value::object() {
    if (!object_) {
        type_ = Type::kObject;
        object_ = std::make_shared<Object>();
    }
    return *object_;
}

size_t Value::size() const {
    if (array_) return array_->size();
    if (object_) return object_->size();
    if (isString()) return string_.size();
    return 0;
}

void Value::push(Value value) {
    if (type_ != Type::kArray) {
        type_ = Type::kArray;
        array_ = std::make_shared<Array>();
    }
    if (!array_) array_ = std::make_shared<Array>();
    array_->push_back(std::move(value));
}

const Array& Value::array() const {
    static const Array kEmpty;
    return array_ ? *array_ : kEmpty;
}

Array& Value::array() {
    if (!array_) {
        type_ = Type::kArray;
        array_ = std::make_shared<Array>();
    }
    return *array_;
}

const Value& Value::at(size_t index) const {
    if (!array_ || index >= array_->size()) return kNull;
    return (*array_)[index];
}

std::string escape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (const char c : text) {
        const unsigned char u = static_cast<unsigned char>(c);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (u < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", u);
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

void Value::dumpTo(std::string& out, bool pretty, int indent, int depth) const {
    switch (type_) {
        case Type::kNull: out += "null"; break;
        case Type::kBool: out += bool_ ? "true" : "false"; break;
        case Type::kNumber: appendNumber(out, number_); break;
        case Type::kString:
            out.push_back('"');
            out += escape(string_);
            out.push_back('"');
            break;
        case Type::kArray: {
            const Array& arr = array();
            if (arr.empty()) {
                out += "[]";
                break;
            }
            out.push_back('[');
            for (size_t i = 0; i < arr.size(); ++i) {
                if (i) out.push_back(',');
                appendIndent(out, pretty, indent, depth + 1);
                arr[i].dumpTo(out, pretty, indent, depth + 1);
            }
            appendIndent(out, pretty, indent, depth);
            out.push_back(']');
            break;
        }
        case Type::kObject: {
            const Object& obj = object();
            if (obj.empty()) {
                out += "{}";
                break;
            }
            out.push_back('{');
            for (size_t i = 0; i < obj.size(); ++i) {
                if (i) out.push_back(',');
                appendIndent(out, pretty, indent, depth + 1);
                out.push_back('"');
                out += escape(obj[i].first);
                out += "\":";
                if (pretty) out.push_back(' ');
                obj[i].second.dumpTo(out, pretty, indent, depth + 1);
            }
            appendIndent(out, pretty, indent, depth);
            out.push_back('}');
            break;
        }
    }
}

std::string Value::dump(bool pretty, int indent) const {
    std::string out;
    dumpTo(out, pretty, indent, 0);
    if (pretty) out.push_back('\n');
    return out;
}

std::string dump(const Value& value, bool pretty, int indent) { return value.dump(pretty, indent); }

Result<Value> parse(std::string_view text) {
    Parser parser(text);
    return parser.parseDocument();
}

}  // namespace netra::json
