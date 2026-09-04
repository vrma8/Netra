// SPDX-License-Identifier: MIT
// filter/filter.cpp : lexer, recursive-descent parser and evaluator.
#include "netra/filter/filter.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <regex>
#include <sstream>

#include "netra/core/log.h"
#include "netra/core/util.h"

namespace netra::filter {
namespace {

// ------------------------------------------------------------------- helpers
bool isIdentChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '-';
}

bool isHexChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

std::string normalizeMac(const std::string& text) {
    std::string out;
    for (const char c : text) {
        if (isHexChar(c)) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

std::string normalizeString(const std::string& text) {
    // For MAC-style comparisons we compare hex digits only, otherwise the raw text.
    if (text.size() >= 11 && text.find(':') != std::string::npos) {
        const std::string digits = normalizeMac(text);
        if (digits.size() == 12) return digits;
    }
    return text;
}

Status errorAt(size_t position, const std::string& message) {
    return Status::invalidArgument("filter error at position " + std::to_string(position) + ": " + message);
}

// -------------------------------------------------------------------- lexer
class Lexer {
public:
    explicit Lexer(std::string_view text) : text_(text) {}

    Result<std::vector<Token>> run() {
        std::vector<Token> tokens;
        while (true) {
            skipWhitespace();
            if (pos_ >= text_.size()) {
                Token end;
                end.type = TokenType::End;
                end.position = pos_;
                tokens.push_back(end);
                return tokens;
            }
            auto token = nextToken();
            if (!token) return token.status();
            tokens.push_back(*token);
        }
    }

private:
    char peek(size_t offset = 0) const {
        return pos_ + offset < text_.size() ? text_[pos_ + offset] : '\0';
    }

    void skipWhitespace() {
        while (pos_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos_]))) ++pos_;
    }

    Result<Token> nextToken() {
        const size_t start = pos_;
        const char c = text_[pos_];

        // Strings
        if (c == '"' || c == '\'') {
            const char quote = c;
            ++pos_;
            std::string value;
            while (pos_ < text_.size() && text_[pos_] != quote) {
                if (text_[pos_] == '\\' && pos_ + 1 < text_.size()) {
                    ++pos_;
                    switch (text_[pos_]) {
                        case 'n': value.push_back('\n'); break;
                        case 'r': value.push_back('\r'); break;
                        case 't': value.push_back('\t'); break;
                        case '\\': value.push_back('\\'); break;
                        case '"': value.push_back('"'); break;
                        case '\'': value.push_back('\''); break;
                        default: value.push_back(text_[pos_]); break;
                    }
                    ++pos_;
                    continue;
                }
                value.push_back(text_[pos_++]);
            }
            if (pos_ >= text_.size()) return errorAt(start, "unterminated string literal");
            ++pos_;  // closing quote
            Token token;
            token.type = TokenType::String;
            token.text = value;
            token.position = start;
            return token;
        }

        // Numbers, IPs, CIDRs, MACs
        if (std::isdigit(static_cast<unsigned char>(c)) || (isHexChar(c) && (peek(1) == ':' || peek(1) == '.'))) {
            return readNumericOrAddress(start);
        }

        // Identifiers and keywords
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            std::string word;
            while (pos_ < text_.size() && isIdentChar(text_[pos_])) word.push_back(text_[pos_++]);

            const std::string lower = util::toLower(word);
            Token token;
            token.position = start;
            token.text = word;
            if (lower == "and" || lower == "&&") {
                token.type = TokenType::And;
            } else if (lower == "or" || lower == "||") {
                token.type = TokenType::Or;
            } else if (lower == "not" || lower == "!") {
                token.type = TokenType::Not;
            } else if (lower == "contains") {
                token.type = TokenType::Contains;
            } else if (lower == "matches" || lower == "~") {
                token.type = TokenType::Matches;
            } else if (lower == "in") {
                token.type = TokenType::In;
            } else if (lower == "true" || lower == "false") {
                token.type = TokenType::Bool;
                token.boolValue = (lower == "true");
            } else {
                token.type = TokenType::Identifier;
            }
            return token;
        }

        // Operators and punctuation
        ++pos_;
        Token token;
        token.position = start;
        token.text = std::string(1, c);
        switch (c) {
            case '=':
                if (peek() == '=') {
                    ++pos_;
                    token.text = "==";
                    token.type = TokenType::Eq;
                } else {
                    token.type = TokenType::Eq;  // single '=' is accepted as equality
                }
                return token;
            case '!':
                if (peek() == '=') {
                    ++pos_;
                    token.text = "!=";
                    token.type = TokenType::Ne;
                } else {
                    token.type = TokenType::Not;
                }
                return token;
            case '<':
                if (peek() == '=') {
                    ++pos_;
                    token.text = "<=";
                    token.type = TokenType::Le;
                } else {
                    token.type = TokenType::Lt;
                }
                return token;
            case '>':
                if (peek() == '=') {
                    ++pos_;
                    token.text = ">=";
                    token.type = TokenType::Ge;
                } else {
                    token.type = TokenType::Gt;
                }
                return token;
            case '&':
                if (peek() == '&') {
                    ++pos_;
                    token.text = "&&";
                    token.type = TokenType::And;
                } else {
                    return errorAt(start, "single '&' is not supported; use '&&' or 'and'");
                }
                return token;
            case '|':
                if (peek() == '|') {
                    ++pos_;
                    token.text = "||";
                    token.type = TokenType::Or;
                } else {
                    return errorAt(start, "single '|' is not supported; use '||' or 'or'");
                }
                return token;
            case '(': token.type = TokenType::LeftParen; return token;
            case ')': token.type = TokenType::RightParen; return token;
            case '[':
            case '{': token.type = TokenType::LeftBracket; return token;
            case ']':
            case '}': token.type = TokenType::RightBracket; return token;
            case ',': token.type = TokenType::Comma; return token;
            default:
                return errorAt(start, std::string("unexpected character '") + c + "'");
        }
    }

    Result<Token> readNumericOrAddress(size_t start) {
        std::string text;
        bool sawColon = false;
        bool sawDot = false;
        bool sawHexPrefix = false;
        while (pos_ < text_.size()) {
            const char c = text_[pos_];
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == ':' || c == '-' || c == '_') {
                if (c == ':') sawColon = true;
                if (c == '.') sawDot = true;
                text.push_back(c);
                ++pos_;
                continue;
            }
            // CIDR suffix: only valid right after an address.
            if (c == '/' && (sawDot || sawColon) && pos_ + 1 < text_.size() &&
                std::isdigit(static_cast<unsigned char>(text_[pos_ + 1]))) {
                text.push_back(c);
                ++pos_;
                while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
                    text.push_back(text_[pos_++]);
                }
                continue;
            }
            break;
        }
        if (util::startsWith(text, "0x") || util::startsWith(text, "0X")) {
            sawHexPrefix = true;
        }
        Token token;
        token.position = start;
        token.text = text;

        if (!sawHexPrefix) {
            if (const size_t slash = text.find('/'); slash != std::string::npos) {
                if (auto cidr = net::Cidr::parse(text)) {
                    token.type = TokenType::Cidr;
                    token.cidrValue = *cidr;
                    return token;
                }
                return errorAt(start, "invalid CIDR literal '" + text + "'");
            }
            if (sawColon || sawDot) {
                if (auto address = net::IpAddr::parse(text)) {
                    token.type = TokenType::Ip;
                    token.ipValue = *address;
                    return token;
                }
            }
        }

        // MAC address literal such as aa:bb:cc:dd:ee:ff
        if (sawColon) {
            const auto parts = util::split(text, ":");
            if (parts.size() == 6 &&
                std::all_of(parts.begin(), parts.end(), [](const std::string& part) {
                    return part.size() <= 2 && !part.empty() &&
                           std::all_of(part.begin(), part.end(), [](char ch) { return isHexChar(ch); });
                })) {
                token.type = TokenType::Bytes;
                token.stringValue = normalizeMac(text);
                if (auto bytes = util::fromHex(text)) token.bytesValue = *bytes;
                return token;
            }
            return errorAt(start, "invalid address literal '" + text + "'");
        }

        // Plain number
        if (sawDot) {
            const auto value = util::parseDouble(text);
            if (!value) return errorAt(start, "invalid numeric literal '" + text + "'");
            token.type = TokenType::Real;
            token.realValue = *value;
            return token;
        }
        const auto value = util::parseInt(text, sawHexPrefix ? 16 : 10);
        if (!value) return errorAt(start, "invalid numeric literal '" + text + "'");
        token.type = TokenType::Number;
        token.intValue = *value;
        return token;
    }

    std::string_view text_;
    size_t pos_{0};
};

// ------------------------------------------------------------------- parser
class Parser {
public:
    explicit Parser(std::vector<Token> tokens) : tokens_(std::move(tokens)) {}

    Result<NodePtr> parse() {
        auto node = parseOr();
        if (!node) return node.status();
        if (current().type != TokenType::End)
            return errorAt(current().position, "unexpected token '" + current().text + "'");
        return std::move(*node);
    }

private:
    const Token& current() const { return tokens_[pos_]; }
    const Token& advance() { return tokens_[pos_++]; }
    bool match(TokenType type) {
        if (current().type == type) {
            ++pos_;
            return true;
        }
        return false;
    }

    Result<NodePtr> parseOr() {
        auto left = parseAnd();
        if (!left) return left.status();
        while (current().type == TokenType::Or) {
            advance();
            auto right = parseAnd();
            if (!right) return right.status();
            auto node = std::make_unique<Node>();
            node->type = NodeType::Logical;
            node->isAnd = false;
            node->left = std::move(*left);
            node->right = std::move(*right);
            left = std::move(node);
        }
        return left;
    }

    Result<NodePtr> parseAnd() {
        auto left = parseUnary();
        if (!left) return left.status();
        while (current().type == TokenType::And) {
            advance();
            auto right = parseUnary();
            if (!right) return right.status();
            auto node = std::make_unique<Node>();
            node->type = NodeType::Logical;
            node->isAnd = true;
            node->left = std::move(*left);
            node->right = std::move(*right);
            left = std::move(node);
        }
        return left;
    }

    Result<NodePtr> parseUnary() {
        if (current().type == TokenType::Not) {
            advance();
            auto operand = parseUnary();
            if (!operand) return operand.status();
            auto node = std::make_unique<Node>();
            node->type = NodeType::Unary;
            node->negate = true;
            node->operand = std::move(*operand);
            return node;
        }
        return parsePrimary();
    }

    Result<NodePtr> parsePrimary() {
        if (current().type == TokenType::LeftParen) {
            advance();
            auto inner = parseOr();
            if (!inner) return inner.status();
            if (!match(TokenType::RightParen)) return errorAt(current().position, "expected ')'");
            return inner;
        }
        if (current().type != TokenType::Identifier)
            return errorAt(current().position, "expected a field name, got '" + current().text + "'");

        Token fieldToken = advance();
        auto node = std::make_unique<Node>();
        node->field = util::toLower(fieldToken.text);
        node->position = fieldToken.position;

        // Comparison?
        switch (current().type) {
            case TokenType::Eq: node->compareOp = Operator::Eq; advance(); break;
            case TokenType::Ne: node->compareOp = Operator::Ne; advance(); break;
            case TokenType::Lt: node->compareOp = Operator::Lt; advance(); break;
            case TokenType::Le: node->compareOp = Operator::Le; advance(); break;
            case TokenType::Gt: node->compareOp = Operator::Gt; advance(); break;
            case TokenType::Ge: node->compareOp = Operator::Ge; advance(); break;
            case TokenType::Contains: node->compareOp = Operator::Contains; advance(); break;
            case TokenType::Matches: node->compareOp = Operator::Matches; advance(); break;
            case TokenType::In:
                node->compareOp = Operator::In;
                advance();
                if (!match(TokenType::LeftBracket)) return errorAt(current().position, "expected '{' or '[' after 'in'");
                while (current().type != TokenType::RightBracket && current().type != TokenType::End) {
                    auto literal = parseLiteral();
                    if (!literal) return literal.status();
                    node->literals.push_back(*literal);
                    if (!match(TokenType::Comma)) break;
                }
                if (!match(TokenType::RightBracket)) return errorAt(current().position, "expected '}' or ']'");
                node->type = NodeType::Comparison;
                return validateField(std::move(node));
            default:
                // Bare field -> existence test.
                node->type = NodeType::Exists;
                return validateField(std::move(node));
        }

        auto literal = parseLiteral();
        if (!literal) return literal.status();
        node->literal = *literal;
        node->type = NodeType::Comparison;
        return validateField(std::move(node));
    }

    Result<Literal> parseLiteral() {
        const Token& token = current();
        Literal literal;
        switch (token.type) {
            case TokenType::Number:
                literal.kind = Literal::Kind::Int;
                literal.intValue = token.intValue;
                break;
            case TokenType::Real:
                literal.kind = Literal::Kind::Real;
                literal.realValue = token.realValue;
                break;
            case TokenType::String:
                literal.kind = Literal::Kind::String;
                literal.stringValue = token.text;
                break;
            case TokenType::Bool:
                literal.kind = Literal::Kind::Bool;
                literal.boolValue = token.boolValue;
                break;
            case TokenType::Ip:
                literal.kind = Literal::Kind::Ip;
                literal.ipValue = token.ipValue;
                break;
            case TokenType::Cidr:
                literal.kind = Literal::Kind::Cidr;
                literal.cidrValue = token.cidrValue;
                break;
            case TokenType::Bytes:
                literal.kind = Literal::Kind::Bytes;
                literal.bytesValue = token.bytesValue;
                literal.stringValue = token.stringValue;
                break;
            case TokenType::Identifier: {
                // Allow unquoted words such as: http.request.method == GET
                const std::string lower = util::toLower(token.text);
                if (lower == "true" || lower == "false") {
                    literal.kind = Literal::Kind::Bool;
                    literal.boolValue = (lower == "true");
                } else {
                    literal.kind = Literal::Kind::String;
                    literal.stringValue = token.text;
                }
                break;
            }
            default:
                return errorAt(token.position, "expected a value, got '" + token.text + "'");
        }
        advance();
        return literal;
    }

    Result<NodePtr> validateField(NodePtr node) {
        if (!fieldExtractor(node->field)) {
            const auto suggestions = fieldSuggestions(node->field, 3);
            std::string message = "unknown field '" + node->field + "'";
            if (!suggestions.empty()) message += " (did you mean " + util::join(suggestions, ", ") + "?)";
            return errorAt(node->position, message);
        }
        return node;
    }

    std::vector<Token> tokens_;
    size_t pos_{0};
};

// ---------------------------------------------------------------- evaluator
double toNumber(const FieldValue& value, size_t index) {
    switch (value.kind) {
        case FieldValue::Kind::Int: return static_cast<double>(value.ints[index]);
        case FieldValue::Kind::Real: return value.reals[index];
        case FieldValue::Kind::Bool: return value.bools[index] ? 1.0 : 0.0;
        case FieldValue::Kind::String: return util::parseDouble(value.strings[index]).value_or(0.0);
        default: return 0.0;
    }
}

double literalNumber(const Literal& literal) {
    switch (literal.kind) {
        case Literal::Kind::Int: return static_cast<double>(literal.intValue);
        case Literal::Kind::Real: return literal.realValue;
        case Literal::Kind::Bool: return literal.boolValue ? 1.0 : 0.0;
        case Literal::Kind::String: return util::parseDouble(literal.stringValue).value_or(0.0);
        default: return 0.0;
    }
}

bool compareScalar(double left, double right, Operator op) {
    switch (op) {
        case Operator::Lt: return left < right;
        case Operator::Le: return left <= right;
        case Operator::Gt: return left > right;
        case Operator::Ge: return left >= right;
        case Operator::Eq: return left == right;
        case Operator::Ne: return left != right;
        default: return false;
    }
}

bool stringContains(const std::string& haystack, const std::string& needle) {
    return needle.empty() || haystack.find(needle) != std::string::npos;
}

bool stringMatches(const std::string& haystack, const std::string& pattern) {
    try {
        static thread_local std::string cachedPattern;
        static thread_local std::regex cachedRegex;
        if (cachedPattern != pattern) {
            cachedRegex = std::regex(pattern, std::regex::ECMAScript);
            cachedPattern = pattern;
        }
        return std::regex_search(haystack, cachedRegex);
    } catch (const std::regex_error& e) {
        log::debugf("invalid regular expression '{}': {}", pattern, e.what());
        return false;
    }
}

bool bytesContain(const std::vector<uint8_t>& haystack, const std::vector<uint8_t>& needle) {
    if (needle.empty()) return true;
    if (needle.size() > haystack.size()) return false;
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

bool evaluateValue(const FieldValue& value, size_t index, Operator op, const Literal& literal) {
    // IP comparisons
    if (value.kind == FieldValue::Kind::Ip) {
        net::IpAddr target;
        net::Cidr cidr;
        bool haveCidr = false;
        if (literal.kind == Literal::Kind::Ip) {
            target = literal.ipValue;
        } else if (literal.kind == Literal::Kind::Cidr) {
            cidr = literal.cidrValue;
            haveCidr = true;
        } else if (literal.kind == Literal::Kind::String) {
            if (literal.stringValue.find('/') != std::string::npos) {
                if (auto parsed = net::Cidr::parse(literal.stringValue)) {
                    cidr = *parsed;
                    haveCidr = true;
                } else {
                    return false;
                }
            } else if (auto parsed = net::IpAddr::parse(literal.stringValue)) {
                target = *parsed;
            } else {
                return false;
            }
        } else {
            return false;
        }
        const net::IpAddr& address = value.ips[index];
        const bool equal = haveCidr ? cidr.contains(address) : (address == target);
        switch (op) {
            case Operator::Eq:
            case Operator::In: return equal;
            case Operator::Ne: return !equal;
            case Operator::Contains:
            case Operator::Matches:
                return stringMatches(address.toString(), literal.stringValue);
            default: return false;
        }
    }

    // Numeric comparisons
    if (value.kind == FieldValue::Kind::Int || value.kind == FieldValue::Kind::Real ||
        value.kind == FieldValue::Kind::Bool) {
        if (literal.kind == Literal::Kind::String && (op == Operator::Contains || op == Operator::Matches)) {
            std::string text;
            if (value.kind == FieldValue::Kind::Bool) text = value.bools[index] ? "true" : "false";
            else if (value.kind == FieldValue::Kind::Int) text = std::to_string(value.ints[index]);
            else text = std::to_string(value.reals[index]);
            return op == Operator::Contains ? stringContains(text, literal.stringValue)
                                            : stringMatches(text, literal.stringValue);
        }
        const double left = toNumber(value, index);
        const double right = literalNumber(literal);
        return compareScalar(left, right, op);
    }

    // String comparisons
    if (value.kind == FieldValue::Kind::String) {
        const std::string& left = value.strings[index];
        if (literal.kind == Literal::Kind::Bytes || literal.kind == Literal::Kind::String) {
            const std::string right = literal.kind == Literal::Kind::Bytes ? normalizeString(literal.stringValue)
                                                                          : literal.stringValue;
            switch (op) {
                case Operator::Eq:
                case Operator::In:
                    return literal.kind == Literal::Kind::Bytes ? normalizeString(left) == right : left == right;
                case Operator::Ne:
                    return literal.kind == Literal::Kind::Bytes ? normalizeString(left) != right : left != right;
                case Operator::Contains: return stringContains(left, right);
                case Operator::Matches: return stringMatches(left, right);
                case Operator::Lt: return left < right;
                case Operator::Le: return left <= right;
                case Operator::Gt: return left > right;
                case Operator::Ge: return left >= right;
            }
        }
        return compareScalar(util::parseDouble(left).value_or(0.0), literalNumber(literal), op);
    }

    // Byte comparisons (raw payload, frame.contains, data)
    if (value.kind == FieldValue::Kind::Bytes) {
        const std::vector<uint8_t>& left = value.bytesList[index];
        std::vector<uint8_t> right;
        if (literal.kind == Literal::Kind::Bytes) {
            right = literal.bytesValue;
        } else if (literal.kind == Literal::Kind::String) {
            if (auto parsed = util::fromHex(literal.stringValue); parsed && literal.stringValue.find(' ') == std::string::npos &&
                                                                   literal.stringValue.find(':') != std::string::npos) {
                right = *parsed;
            } else {
                right.assign(literal.stringValue.begin(), literal.stringValue.end());
            }
        } else {
            return false;
        }
        switch (op) {
            case Operator::Eq:
            case Operator::In: return left == right;
            case Operator::Ne: return left != right;
            case Operator::Contains: return bytesContain(left, right);
            case Operator::Matches: {
                const std::string text(left.begin(), left.end());
                const std::string pattern(right.begin(), right.end());
                return stringMatches(text, pattern);
            }
            default: return false;
        }
    }
    return false;
}

bool evaluate(const Node& node, const decode::DecodedPacket& packet) {
    switch (node.type) {
        case NodeType::Logical: {
            const bool left = evaluate(*node.left, packet);
            if (node.isAnd) return left && evaluate(*node.right, packet);
            return left || evaluate(*node.right, packet);
        }
        case NodeType::Unary:
            return node.negate ? !evaluate(*node.operand, packet) : evaluate(*node.operand, packet);
        case NodeType::Exists: {
            const FieldExtractor extractor = fieldExtractor(node.field);
            if (!extractor) return false;
            const FieldValue value = extractor(packet);
            if (!value.present()) return false;
            if (value.kind == FieldValue::Kind::Bool) {
                for (const bool entry : value.bools)
                    if (entry) return true;
                return false;
            }
            return value.count() > 0;
        }
        case NodeType::Comparison: {
            const FieldExtractor extractor = fieldExtractor(node.field);
            if (!extractor) return false;
            const FieldValue value = extractor(packet);
            if (!value.present()) return false;
            if (node.compareOp == Operator::In) {
                for (const auto& literal : node.literals) {
                    for (size_t i = 0; i < value.count(); ++i) {
                        if (evaluateValue(value, i, Operator::Eq, literal)) return true;
                    }
                }
                return false;
            }
            // `!=` is the negation of `==`: it only holds when *no* entry of a
            // (possibly aggregate) field equals the literal.
            if (node.compareOp == Operator::Ne) {
                if (value.count() == 0) return false;
                for (size_t i = 0; i < value.count(); ++i) {
                    if (evaluateValue(value, i, Operator::Eq, node.literal)) return false;
                }
                return true;
            }
            for (size_t i = 0; i < value.count(); ++i) {
                if (evaluateValue(value, i, node.compareOp, node.literal)) return true;
            }
            return false;
        }
    }
    return false;
}

}  // namespace

const char* operatorName(Operator op) {
    switch (op) {
        case Operator::Eq: return "==";
        case Operator::Ne: return "!=";
        case Operator::Lt: return "<";
        case Operator::Le: return "<=";
        case Operator::Gt: return ">";
        case Operator::Ge: return ">=";
        case Operator::Contains: return "contains";
        case Operator::Matches: return "matches";
        case Operator::In: return "in";
    }
    return "?";
}

std::string Literal::toString() const {
    switch (kind) {
        case Kind::Bool: return boolValue ? "true" : "false";
        case Kind::Int: return std::to_string(intValue);
        case Kind::Real: return std::to_string(realValue);
        case Kind::String: return "\"" + stringValue + "\"";
        case Kind::Ip: return ipValue.toString();
        case Kind::Cidr: return cidrValue.toString();
        case Kind::Bytes: return stringValue.empty() ? util::toHex(ByteView(bytesValue), ":") : stringValue;
    }
    return "?";
}

std::string Node::toString() const {
    switch (type) {
        case NodeType::Logical:
            return "(" + left->toString() + (isAnd ? " && " : " || ") + right->toString() + ")";
        case NodeType::Unary:
            return std::string(negate ? "!(" : "(") + operand->toString() + ")";
        case NodeType::Exists:
            return field;
        case NodeType::Comparison: {
            std::string out = field + " " + operatorName(compareOp) + " ";
            if (compareOp == Operator::In) {
                std::vector<std::string> parts;
                for (const auto& item : literals) parts.push_back(item.toString());
                out += "{" + util::join(parts, ", ") + "}";
            } else {
                out += literal.toString();
            }
            return out;
        }
    }
    return "?";
}

Result<std::vector<Token>> tokenize(std::string_view expression) {
    Lexer lexer(expression);
    return lexer.run();
}

Result<Filter> Filter::compile(std::string_view expression) {
    Filter filter;
    const std::string text = util::trim(expression);
    filter.expression_ = text;
    if (text.empty()) return filter;  // an empty filter matches everything

    auto tokens = tokenize(text);
    if (!tokens) return tokens.status();

    Parser parser(std::move(*tokens));
    auto root = parser.parse();
    if (!root) return root.status();

    filter.root_ = std::move(*root);
    return filter;
}

Status Filter::validate(std::string_view expression) {
    auto filter = compile(expression);
    return filter.ok() ? Status::success() : filter.status();
}

bool Filter::matches(const decode::DecodedPacket& packet) const {
    if (!root_) return true;
    return evaluate(*root_, packet);
}

}  // namespace netra::filter
