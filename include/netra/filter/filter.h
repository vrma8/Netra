// SPDX-License-Identifier: MIT
// filter/filter.h : Wireshark-style display filter engine.
//
// Grammar (see docs/filters.md):
//
//   expression := orExpr
//   orExpr     := andExpr { ("||"|"or") andExpr }
//   andExpr    := unary  { ("&&"|"and") unary }
//   unary      := ("!"|"not") unary | primary
//   primary    := "(" expression ")" | comparison | exists
//   comparison := field op value
//   op         := "==" "!=" "<" "<=" ">" ">=" "contains" "matches" "in"
//   value      := number | string | ip | cidr | bytes | true | false
//   exists     := field
//
// Fields follow the dotted Wireshark naming scheme, e.g. `tcp.port == 80`,
// `ip.addr == 10.0.0.0/24`, `dns.qry.name contains "github"`, `http.request`.
#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "netra/core/status.h"
#include "netra/decode/packet.h"
#include "netra/net/ip.h"

namespace netra::filter {

enum class TokenType {
    End,
    Identifier,
    Number,
    Real,
    String,
    Ip,
    Cidr,
    Bytes,
    Bool,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    Matches,
    In,
    And,
    Or,
    Not,
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    Comma,
};

struct Token {
    TokenType type{TokenType::End};
    std::string text;
    int64_t intValue{0};
    double realValue{0};
    bool boolValue{false};
    std::string stringValue;               // normalised text for bytes/MAC literals
    std::vector<uint8_t> bytesValue;
    net::IpAddr ipValue;
    net::Cidr cidrValue;
    size_t position{0};
};

enum class Operator { Eq, Ne, Lt, Le, Gt, Ge, Contains, Matches, In };
const char* operatorName(Operator op);

/// A field value can carry several entries so that aggregate fields such as
/// `ip.addr` (source OR destination) match if any entry satisfies the test.
struct FieldValue {
    enum class Kind { None, Bool, Int, Real, String, Ip, Bytes };
    Kind kind{Kind::None};
    std::vector<bool> bools;
    std::vector<int64_t> ints;
    std::vector<double> reals;
    std::vector<std::string> strings;
    std::vector<net::IpAddr> ips;
    std::vector<std::vector<uint8_t>> bytesList;

    static FieldValue none();
    static FieldValue boolean(bool value);
    static FieldValue integer(int64_t value);
    static FieldValue real(double value);
    static FieldValue string(std::string value);
    static FieldValue ip(net::IpAddr value);
    static FieldValue bytes(std::vector<uint8_t> value);

    bool present() const { return kind != Kind::None; }
    size_t count() const;
    void add(FieldValue other);
};

/// Literal on the right hand side of a comparison.
struct Literal {
    enum class Kind { Bool, Int, Real, String, Ip, Cidr, Bytes };
    Kind kind{Kind::Int};
    bool boolValue{false};
    int64_t intValue{0};
    double realValue{0};
    std::string stringValue;
    net::IpAddr ipValue;
    net::Cidr cidrValue;
    std::vector<uint8_t> bytesValue;

    std::string toString() const;
};

struct Node;
using NodePtr = std::unique_ptr<Node>;

enum class NodeType { Logical, Unary, Comparison, Exists };

struct Node {
    NodeType type{NodeType::Exists};
    // Logical
    bool isAnd{false};
    NodePtr left;
    NodePtr right;
    // Unary
    bool negate{false};
    NodePtr operand;
    // Comparison / Exists
    std::string field;
    Operator compareOp{Operator::Eq};
    Literal literal;
    // "in {a, b, c}"
    std::vector<Literal> literals;
    size_t position{0};

    std::string toString() const;
};

/// Extracts a field from a decoded packet. Returns FieldValue::none() when the
/// field does not apply to this packet.
using FieldExtractor = FieldValue (*)(const decode::DecodedPacket& packet);

struct FieldInfo {
    std::string name;
    std::string type;        // "bool", "int", "string", "ip", "bytes"
    std::string description;
    std::string example;
};

/// Compiled filter. Instances are immutable and safe to share between threads.
class Filter {
public:
    Filter() = default;

    static Result<Filter> compile(std::string_view expression);
    static Status validate(std::string_view expression);

    bool matches(const decode::DecodedPacket& packet) const;
    bool empty() const { return !root_; }
    const std::string& expression() const { return expression_; }
    std::string describe() const { return root_ ? root_->toString() : "(empty)"; }

private:
    NodePtr root_;
    std::string expression_;
};

/// Registry of every field the engine understands.
const std::vector<FieldInfo>& fieldRegistry();
/// Looks up an extractor; nullptr when the field is unknown.
FieldExtractor fieldExtractor(const std::string& name);
/// Suggests close matches for a typo'd field name.
std::vector<std::string> fieldSuggestions(const std::string& name, size_t limit = 5);
/// Tokeniser, exposed for tests.
Result<std::vector<Token>> tokenize(std::string_view expression);

}  // namespace netra::filter
