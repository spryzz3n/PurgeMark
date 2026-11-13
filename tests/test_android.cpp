// Station side of the phone flow: challenge encoding and record rejection.

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

#include "check.hpp"
#include "pm/android_record.hpp"
#include "pm/crypto.hpp"

using nlohmann::json;

static void test_base64url() {
    const std::vector<std::uint8_t> bytes = {0xfb, 0xff, 0xfe, 0x00, 0x01};
    const std::string text = pm::base64url_encode(bytes);
    CHECK(text.find_first_of("+/=") == std::string::npos);
    const auto back = pm::base64url_decode(text);
    CHECK(back && back.value() == bytes);
    CHECK(!pm::base64url_decode("ab+/"));
}

static void test_challenge() {
    const auto bytes = pm::random_bytes(pm::kChallengeSize);
    const auto parsed = pm::parse_challenge_payload(pm::challenge_payload(bytes));
    CHECK(parsed && parsed.value() == bytes);

    CHECK(!pm::parse_challenge_payload("hello"));
    CHECK(!pm::parse_challenge_payload(std::string(pm::kChallengePrefix) + "AAAA"));  // too short
}

static void test_bad_records() {
    CHECK(!pm::check_android_record(json::array(), std::nullopt, std::nullopt).error.empty());
    CHECK(!pm::check_android_record({{"schema", "other"}}, std::nullopt, std::nullopt).error.empty());
    // Right schema, missing everything else: reported, not thrown.
    CHECK(!pm::check_android_record({{"schema", pm::kAndroidRecordSchema}}, std::nullopt, std::nullopt).error.empty());

    const json garbage = {{"schema", pm::kAndroidRecordSchema},
                          {"key", {{"attestation_chain", {"AAAA", "AAAA"}}}}};
    CHECK(!pm::check_android_record(garbage, std::nullopt, std::nullopt).error.empty());
}

static void test_passed_needs_everything() {
    pm::AndroidRecordCheck c;
    c.signature_ok = c.chain_ok = c.challenge_in_attestation = c.level_consistent = true;
    c.challenge_expected = true;
    c.root_trusted = true;
    c.security_level = "tee";
    CHECK(c.passed());

    auto software = c;
    software.security_level = "software";
    CHECK(!software.passed());

    auto no_root = c;
    no_root.root_trusted.reset();  // an unchecked root is not a pass
    CHECK(!no_root.passed());

    auto wrong_challenge = c;
    wrong_challenge.challenge_expected = false;
    CHECK(!wrong_challenge.passed());
}

int main() {
    test_base64url();
    test_challenge();
    test_bad_records();
    test_passed_needs_everything();
    return finish("android");
}
