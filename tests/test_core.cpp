// SPDX-License-Identifier: MIT
// tests/test_core.cpp : core utilities - strings, JSON, formatting, args, status.

#include <string>
#include <vector>

#include "harness.h"
#include "netra/core/args.h"
#include "netra/core/fmt.h"
#include "netra/core/json.h"
#include "netra/core/log.h"
#include "netra/core/status.h"
#include "netra/core/util.h"

using namespace netra;  // NOLINT

NETRA_TEST(core, stringHelpers) {
    NETRA_CHECK_EQ(util::trim("  hello \t"), std::string("hello"));
    NETRA_CHECK_EQ(util::toLower("AbC"), std::string("abc"));
    NETRA_CHECK_EQ(util::toUpper("AbC"), std::string("ABC"));
    NETRA_CHECK(util::startsWith("netra scan", "netra"));
    NETRA_CHECK(!util::startsWith("netra", "scan"));
    NETRA_CHECK(util::endsWith("capture.pcap", ".pcap"));
    NETRA_CHECK(util::containsInsensitive("Hello World", "lo wo"));
    NETRA_CHECK_EQ(util::replaceAll("a-b-c", "-", "+"), std::string("a+b+c"));

    const auto parts = util::split("22,80,443", ",");
    NETRA_CHECK_EQ(parts.size(), size_t{3});
    NETRA_CHECK_EQ(parts[1], std::string("80"));
    NETRA_CHECK_EQ(util::join(parts, "/"), std::string("22/80/443"));

    const auto lines = util::splitLines("one\ntwo\nthree");
    NETRA_CHECK_EQ(lines.size(), size_t{3});
    NETRA_CHECK_EQ(lines[2], std::string("three"));

    NETRA_CHECK_EQ(util::pad("ab", 5, true), std::string("ab   "));
    NETRA_CHECK_EQ(util::pad("ab", 5, false), std::string("   ab"));
    NETRA_CHECK_EQ(util::truncate("abcdefgh", 5), std::string("ab..."));
    NETRA_CHECK_EQ(util::truncate("abc", 5), std::string("abc"));
}

NETRA_TEST(core, numberParsing) {
    NETRA_CHECK(util::parseInt("42").value_or(-1) == 42);
    NETRA_CHECK(util::parseInt("-7").value_or(0) == -7);
    NETRA_CHECK(!util::parseInt("12ab").has_value());
    NETRA_CHECK(util::parseDouble("1.5").value_or(0) == 1.5);
    NETRA_CHECK(util::parseSize("512").value_or(0) == 512);
    NETRA_CHECK(util::parseSize("4K").value_or(0) == 4096);
    NETRA_CHECK(util::parseSize("2MB").value_or(0) == 2u * 1024u * 1024u);
    NETRA_CHECK(!util::parseSize("nonsense").has_value());
    NETRA_CHECK(util::parseDuration("250ms").value_or(std::chrono::milliseconds(0)) == std::chrono::milliseconds(250));
    NETRA_CHECK(util::parseDuration("2s").value_or(std::chrono::milliseconds(0)) == std::chrono::milliseconds(2000));
    NETRA_CHECK(util::parseDuration("1m").value_or(std::chrono::milliseconds(0)) == std::chrono::milliseconds(60000));
    NETRA_CHECK_EQ(util::percent(50, 200), std::string("25.0%"));
    NETRA_CHECK_EQ(util::percent(0, 0), std::string("0.0%"));
    NETRA_CHECK(!util::humanBytes(1536).empty());
    NETRA_CHECK(!util::humanRate(1500000).empty());
}

NETRA_TEST(core, hexHelpers) {
    const std::vector<uint8_t> data = {0xde, 0xad, 0xbe, 0xef};
    NETRA_CHECK_EQ(util::toHex(ByteView(data)), std::string("deadbeef"));
    NETRA_CHECK_EQ(util::toHex(ByteView(data), ":"), std::string("de:ad:be:ef"));
    const auto parsed = util::fromHex("deadbeef");
    NETRA_CHECK(parsed.has_value());
    NETRA_CHECK_EQ(parsed->size(), size_t{4});
    NETRA_CHECK((*parsed)[0] == 0xde);
    NETRA_CHECK(!util::fromHex("zz").has_value());
    NETRA_CHECK(util::hexDump(ByteView(data)).find("de ad") != std::string::npos);
    NETRA_CHECK_EQ(util::asciiPreview(ByteView("hello", 5)), std::string("hello"));
    NETRA_CHECK(util::fnv1a(ByteView(data)) == util::fnv1a(ByteView(data)));
}

NETRA_TEST(core, pathAndTimeHelpers) {
    NETRA_CHECK_EQ(util::parentDir("/tmp/a/b.pcap"), std::string("/tmp/a"));
    NETRA_CHECK_EQ(util::pathJoin("/tmp/a", "b.pcap"), std::string("/tmp/a/b.pcap"));
    NETRA_CHECK(util::fileExists("/tmp"));
    NETRA_CHECK(util::isDirectory("/tmp"));
    NETRA_CHECK(!util::fileExists("/tmp/definitely-not-here-netra"));
    const std::string stamp = util::formatTimestamp(1700000000, 500000, true);
    NETRA_CHECK(stamp.find("2023-11-14") != std::string::npos);
    NETRA_CHECK(!util::isoTimestamp(1700000000).empty());
    NETRA_CHECK(util::monotonicMillis() > 0);
    NETRA_CHECK(util::hardwareConcurrency() >= 1);
    NETRA_CHECK(!util::hostname().empty());
    NETRA_CHECK(!util::osName().empty());
    NETRA_CHECK_EQ(util::randomHex(4).size(), size_t{8});
}

NETRA_TEST(core, fileReadWrite) {
    const std::string path = "/tmp/netra-test-file-" + std::to_string(util::currentPid()) + ".txt";
    const Status written = util::writeFile(path, std::string_view("line one\nline two\n"));
    NETRA_CHECK_MSG(written.ok(), written.message());
    const auto text = util::readTextFile(path);
    NETRA_CHECK(text.ok());
    NETRA_CHECK_EQ(*text, std::string("line one\nline two\n"));
    const Status appended = util::writeFile(path, std::string_view("line three\n"), true);
    NETRA_CHECK(appended.ok());
    NETRA_CHECK_EQ(util::splitLines(*util::readTextFile(path)).size(), size_t{3});
    const auto missing = util::readFile("/tmp/netra-missing-file-xyz");
    NETRA_CHECK(!missing.ok());
    std::remove(path.c_str());
}

NETRA_TEST(core, formatPlaceholders) {
    NETRA_CHECK_EQ(fmt::format("plain"), std::string("plain"));
    NETRA_CHECK_EQ(fmt::format("{} + {} = {}", 1, 2, 3), std::string("1 + 2 = 3"));
    NETRA_CHECK_EQ(fmt::format("{}%", 42), std::string("42%"));
    NETRA_CHECK_EQ(fmt::format("escaped {{}} braces"), std::string("escaped {} braces"));
    NETRA_CHECK_EQ(fmt::format("mixed {} and {}", "a", 1.5), std::string("mixed a and 1.5"));
    // More arguments than placeholders are dropped, fewer leaves the token in place.
    NETRA_CHECK_EQ(fmt::format("one {}", 1, 2), std::string("one 1"));
    NETRA_CHECK_EQ(fmt::format("two {} {}"), std::string("two {} {}"));
}

NETRA_TEST(core, statusAndResult) {
    NETRA_CHECK(Status::success().ok());
    NETRA_CHECK_EQ(Status::success().code(), StatusCode::Ok);
    const Status denied = Status::permissionDenied("need root");
    NETRA_CHECK(!denied.ok());
    NETRA_CHECK_EQ(denied.code(), StatusCode::PermissionDenied);
    NETRA_CHECK(denied.message().find("need root") != std::string::npos);
    NETRA_CHECK(std::string(statusCodeName(StatusCode::NotFound)).size() > 0);
    NETRA_CHECK(std::string(statusCodeName(StatusCode::Ok)) != std::string(statusCodeName(StatusCode::NotFound)));

    Result<int> value(7);
    NETRA_CHECK(value.ok());
    NETRA_CHECK_EQ(*value, 7);
    NETRA_CHECK_EQ(value.valueOr(0), 7);

    Result<int> error(Status::notFound("nope"));
    NETRA_CHECK(!error.ok());
    NETRA_CHECK_EQ(error.valueOr(3), 3);
    NETRA_CHECK(error.message().find("nope") != std::string::npos);
}

NETRA_TEST(core, jsonValues) {
    json::Value value = json::Value::obj();
    value["string"] = "text";
    value["int"] = 42;
    value["negative"] = -7;
    value["real"] = 1.25;
    value["boolean"] = true;
    value["nothing"] = json::Value::null();
    json::Array array;
    array.push_back(1);
    array.push_back(std::string("two"));
    value["array"] = array;
    value["nested"] = json::Value::obj();
    value["nested"]["deep"] = "yes";

    NETRA_CHECK(value.isObject());
    NETRA_CHECK(value.find("string") != nullptr);
    NETRA_CHECK_EQ(value.find("string")->asString(), std::string("text"));
    NETRA_CHECK_EQ(value.find("int")->asInt(), int64_t{42});
    NETRA_CHECK(value.find("boolean")->asBool());
    NETRA_CHECK(value.find("nothing")->isNull());
    NETRA_CHECK_EQ(value.find("array")->size(), size_t{2});
    NETRA_CHECK_EQ(value.find("array")->at(1).asString(), std::string("two"));
    NETRA_CHECK_EQ(value.find("nested")->find("deep")->asString(), std::string("yes"));
    NETRA_CHECK(value.find("missing") == nullptr);
    NETRA_CHECK(!value.contains("missing"));

    const std::string text = value.dump();
    const auto parsed = json::parse(text);
    NETRA_CHECK_MSG(parsed.ok(), parsed.message());
    NETRA_CHECK_EQ(parsed->find("int")->asInt(), int64_t{42});
    NETRA_CHECK_EQ(parsed->find("nested")->find("deep")->asString(), std::string("yes"));
    const std::string pretty = value.dump(2);
    NETRA_CHECK(pretty.find('\n') != std::string::npos);
}

NETRA_TEST(core, jsonParsing) {
    const auto object = json::parse(R"({"a": 1, "b": [true, false, null], "c": "x\ny"})");
    NETRA_CHECK_MSG(object.ok(), object.message());
    NETRA_CHECK_EQ(object->find("a")->asInt(), int64_t{1});
    NETRA_CHECK(object->find("b")->at(0).asBool());
    NETRA_CHECK(!object->find("b")->at(1).asBool());
    NETRA_CHECK(object->find("b")->at(2).isNull());
    NETRA_CHECK(object->find("c")->asString().find('\n') != std::string::npos);

    const auto number = json::parse("3.5e2");
    NETRA_CHECK(number.ok());
    NETRA_CHECK(number->asNumber() == 350.0);

    const auto array = json::parse("[1,2,3]");
    NETRA_CHECK(array.ok());
    NETRA_CHECK_EQ(array->size(), size_t{3});

    NETRA_CHECK(!json::parse("{").ok());
    NETRA_CHECK(!json::parse("{\"a\":}").ok());
    NETRA_CHECK(!json::parse("nonsense").ok());
}

NETRA_TEST(core, argParserBasics) {
    cli::ArgParser parser;
    parser.flag("verbose", "v", "verbose");
    parser.flag("color", "", "colour");
    parser.value("ports", "p", "SPEC", "ports", "top100");
    parser.multi("exclude", "", "SPEC", "exclude");
    parser.positional({"targets", "targets", false, true});

    const auto parsed = parser.parse({"-v", "--ports", "22,80", "--exclude", "10.0.0.1", "--exclude", "10.0.0.2",
                                      "--color=false", "192.168.0.1", "example.com"});
    NETRA_CHECK_MSG(parsed.ok(), parsed.message());
    NETRA_CHECK(parsed->flag("verbose"));
    NETRA_CHECK_EQ(parsed->get("ports"), std::string("22,80"));
    NETRA_CHECK_EQ(parsed->getAll("exclude").size(), size_t{2});
    NETRA_CHECK(!parsed->getBool("color", true));
    NETRA_CHECK_EQ(parsed->positional().size(), size_t{2});
    NETRA_CHECK_EQ(parsed->positional(1), std::string("example.com"));
}

NETRA_TEST(core, argParserNmapStyle) {
    cli::ArgParser parser;
    parser.flag("syn", "sS", "syn scan");
    parser.flag("service", "sV", "version scan");
    parser.flag("ping", "sn", "discovery only");
    parser.value("ports", "p", "SPEC", "ports", "top100");
    parser.value("timing", "T", "N", "timing", "3");
    parser.positional({"targets", "targets", false, true});

    const auto parsed = parser.parse({"-sS", "-sV", "-p1-1024", "-T4", "10.0.0.0/24"});
    NETRA_CHECK_MSG(parsed.ok(), parsed.message());
    NETRA_CHECK(parsed->flag("syn"));
    NETRA_CHECK(parsed->flag("service"));
    NETRA_CHECK(!parsed->flag("ping"));
    NETRA_CHECK_EQ(parsed->get("ports"), std::string("1-1024"));
    NETRA_CHECK_EQ(parsed->getInt("timing", 0), int64_t{4});
    NETRA_CHECK_EQ(parsed->positional(0), std::string("10.0.0.0/24"));

    // Clustered flags and inline long values.
    const auto clustered = parser.parse({"-sSsn", "--ports=80,443", "--", "-weird-target"});
    NETRA_CHECK_MSG(clustered.ok(), clustered.message());
    NETRA_CHECK(clustered->flag("syn"));
    NETRA_CHECK(clustered->flag("ping"));
    NETRA_CHECK_EQ(clustered->get("ports"), std::string("80,443"));
    NETRA_CHECK_EQ(clustered->positional(0), std::string("-weird-target"));
}

NETRA_TEST(core, argParserOptionalValue) {
    cli::ArgParser parser;
    parser.optionalValue("store", "", "PATH", "persist this run");
    parser.flag("no-store", "", "do not persist");
    parser.value("ports", "p", "SPEC", "ports", "top100");
    parser.positional({"targets", "targets", true, true});

    // Bare option: presence with an empty value, following tokens stay positional.
    const auto bare = parser.parse({"--store", "10.0.0.1", "10.0.0.2"});
    NETRA_CHECK_MSG(bare.ok(), bare.message());
    NETRA_CHECK(bare->has("store"));
    NETRA_CHECK_EQ(bare->get("store"), std::string(""));
    NETRA_CHECK_EQ(bare->positional().size(), size_t{2});
    NETRA_CHECK_EQ(bare->positional(0), std::string("10.0.0.1"));

    // Inline value.
    const auto inlineValue = parser.parse({"--store=/tmp/lab.jsonl", "10.0.0.1"});
    NETRA_CHECK_MSG(inlineValue.ok(), inlineValue.message());
    NETRA_CHECK_EQ(inlineValue->get("store"), std::string("/tmp/lab.jsonl"));
    NETRA_CHECK_EQ(inlineValue->positional().size(), size_t{1});

    // Absent option and the negating flag are independent.
    const auto absent = parser.parse({"--no-store", "10.0.0.1"});
    NETRA_CHECK_MSG(absent.ok(), absent.message());
    NETRA_CHECK(!absent->has("store"));
    NETRA_CHECK(absent->flag("no-store"));

    // Usage shows the optional value.
    NETRA_CHECK(parser.usage("netra scan").find("--store[=PATH]") != std::string::npos);
}

NETRA_TEST(core, argParserErrors) {
    cli::ArgParser parser;
    parser.value("ports", "p", "SPEC", "ports");
    parser.positional({"target", "target", true, false});

    NETRA_CHECK(!parser.parse({"--bogus"}).ok());
    NETRA_CHECK(!parser.parse({"-p"}).ok());
    NETRA_CHECK(!parser.parse({}).ok());  // missing required positional
    NETRA_CHECK(parser.parse({"-p", "80", "host"}).ok());
    NETRA_CHECK(!parser.usage("netra scan").empty());
}

NETRA_TEST(core, loggerLevels) {
    auto& logger = log::Logger::instance();
    const auto previous = logger.level();
    logger.setLevel(log::Level::Error);
    NETRA_CHECK(!logger.enabled(log::Level::Info));
    NETRA_CHECK(logger.enabled(log::Level::Error));
    logger.setLevel(log::Level::Trace);
    NETRA_CHECK(logger.enabled(log::Level::Debug));
    NETRA_CHECK(!log::levelName(log::Level::Warn).empty());
    NETRA_CHECK(log::levelFromString("debug") == log::Level::Debug);
    logger.setLevel(previous);
}
