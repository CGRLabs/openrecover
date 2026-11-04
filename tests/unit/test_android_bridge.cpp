#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fake_adb_transport.hpp"
#include "openrecover/android/android_bridge.hpp"
#include "openrecover/android/scan_profile.hpp"
#include "openrecover/common/error.hpp"
#include "openrecover/common/path_util.hpp"
#include "test_util.hpp"

#ifndef OPENRECOVER_ANDROID_FIXTURE_DIR
#error "OPENRECOVER_ANDROID_FIXTURE_DIR must point at the fake sdcard tree"
#endif
#ifndef OPENRECOVER_PROFILE_DIR
#error "OPENRECOVER_PROFILE_DIR must point at the shipped profiles"
#endif

using namespace openrecover;
using namespace openrecover::android;

namespace fs = std::filesystem;

namespace {

const fs::path kFixture = fs::path(OPENRECOVER_ANDROID_FIXTURE_DIR);
const fs::path kProfiles = fs::path(OPENRECOVER_PROFILE_DIR);
constexpr const char* kSerial = "FAKE1234";

AndroidScanProfile default_profile() {
    auto profile = load_scan_profile(kProfiles / "default.json");
    REQUIRE(profile.has_value());
    return std::move(*profile);
}

const AndroidFile* find_file(const AndroidScanResult& result, std::string_view remote) {
    for (const AndroidFile& file : result.files) {
        if (file.remote_path == remote) return &file;
    }
    return nullptr;
}

const AndroidRootResult* find_root(const AndroidScanResult& result, std::string_view id) {
    for (const AndroidRootResult& root : result.roots) {
        if (root.id == id) return &root;
    }
    return nullptr;
}

bool any_warning_contains(const AndroidScanResult& result, std::string_view needle) {
    return std::any_of(result.warnings.begin(), result.warnings.end(),
                       [&](const std::string& warning) { return warning.find(needle) != std::string::npos; });
}

int64_t unix_seconds(fs::file_time_type time) {
#if defined(_MSC_VER)
    const auto sys = std::chrono::clock_cast<std::chrono::system_clock>(time);
#else
    const auto sys = std::chrono::file_clock::to_sys(time);
#endif
    return std::chrono::duration_cast<std::chrono::seconds>(sys.time_since_epoch()).count();
}

fs::path fixture_file(std::string_view remote) {
    return kFixture / path_from_utf8(std::string(remote.substr(std::string_view("/sdcard/").size())));
}

AndroidBridgeOptions pull_options(const fs::path& out, const fs::path& temp) {
    AndroidBridgeOptions options;
    options.out_dir = out;
    options.temp_dir = temp;
    return options;
}

}  // namespace

TEST_CASE("default and vendor profiles load", "[android][profile]") {
    auto profile = default_profile();
    CHECK(profile.schema == 1);
    CHECK(profile.name == "default");
    REQUIRE(profile.roots.size() == 4);

    CHECK(profile.roots[0].id == "thumbnails");
    CHECK(profile.roots[0].path == "/sdcard/DCIM/.thumbnails");
    CHECK(profile.roots[0].kind == AndroidRootKind::Thumbnail);
    CHECK(profile.roots[0].recursive);
    CHECK(profile.roots[0].max_depth == -1);
    CHECK_FALSE(profile.roots[0].optional);

    CHECK(profile.roots[2].id == "trashed_media");
    CHECK(profile.roots[2].kind == AndroidRootKind::Trash);
    CHECK(profile.roots[2].max_depth == 6);
    REQUIRE(profile.roots[2].name_pattern.has_value());
    CHECK(std::regex_match(".trashed-1735689600-IMG_1.jpg", *profile.roots[2].name_pattern));
    CHECK_FALSE(std::regex_match("IMG_1.jpg", *profile.roots[2].name_pattern));

    CHECK(profile.roots[3].id == "app_media_cache");
    CHECK(profile.roots[3].kind == AndroidRootKind::Cache);
    CHECK(profile.roots[3].optional);
    REQUIRE(profile.roots[3].dir_pattern.has_value());
    CHECK(std::regex_search("/sdcard/Android/data/com.x/cache", *profile.roots[3].dir_pattern));
    CHECK_FALSE(std::regex_search("/sdcard/Android/data/com.x/files", *profile.roots[3].dir_pattern));

    CHECK(profile.type_filter.size() == 13);
    CHECK(profile.max_file_size == 2147483648ull);

    auto vendor = load_scan_profile(kProfiles / "vendor_examples.json");
    REQUIRE(vendor.has_value());
    CHECK(vendor->name == "vendor_examples");
    CHECK(vendor->roots.size() == 5);
    for (const AndroidScanRoot& root : vendor->roots) {
        CHECK(root.optional);
    }
}

TEST_CASE("profile parser rejects malformed or unsafe documents", "[android][profile]") {
    const std::string good_root =
        R"({"id":"r","path":"/sdcard/DCIM/.thumbnails","kind":"thumbnail"})";
    const auto rejected = [](const std::string& json) {
        auto result = parse_scan_profile(json, "test");
        return !result && result.error().code == ErrorCode::InvalidArgument;
    };

    CHECK(rejected(""));
    CHECK(rejected("{"));
    CHECK(rejected("[]"));
    CHECK(rejected(R"({"schema":2,"name":"x","roots":[)" + good_root + "]}"));
    CHECK(rejected(R"({"schema":1,"roots":[)" + good_root + "]}"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[)" + good_root + R"(],"extra":1})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[{"id":"r","path":"/data/data/com.x","kind":"thumbnail"}]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[{"id":"r","path":"/sdcard/DCIM/../x","kind":"thumbnail"}]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[{"id":"r","path":"/sdcard/DCIM","kind":"thumbnail","bogus":true}]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[{"id":"a/b","path":"/sdcard/DCIM","kind":"thumbnail"}]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[{"id":"r","path":"/sdcard/DCIM","kind":"other"}]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[{"id":"r","path":"/sdcard/DCIM","kind":"thumbnail","name_regex":"("}]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[{"id":"r","path":"/sdcard/DCIM","kind":"thumbnail","max_depth":0}]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[{"id":"r","path":"/sdcard/DCIM","kind":"thumbnail","max_depth":65}]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[{"id":"r","path":"/sdcard/DCIM","kind":"thumbnail"},{"id":"r","path":"/sdcard/Pictures","kind":"thumbnail"}]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[)" + good_root + R"(],"type_filter":["jp g"]})"));
    CHECK(rejected(R"({"schema":1,"name":"x","roots":[)" + good_root + R"(],"max_file_size":0})"));

    auto duplicate = parse_scan_profile(
        R"({"schema":1,"name":"x","roots":[{"id":"r","path":"/sdcard/A","kind":"thumbnail"},{"id":"r","path":"/sdcard/B","kind":"thumbnail"}]})",
        "test");
    REQUIRE_FALSE(duplicate.has_value());
    CHECK(duplicate.error().code == ErrorCode::InvalidArgument);

    auto missing = load_scan_profile(kProfiles / "does-not-exist.json");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error().code == ErrorCode::NotFound);
}

TEST_CASE("trashed media names parse", "[android][profile]") {
    auto name = parse_trashed_name(".trashed-1735689600-IMG_1.jpg");
    REQUIRE(name.has_value());
    CHECK(name->expires_at == 1735689600ull);
    CHECK(name->original_name == "IMG_1.jpg");

    CHECK(parse_trashed_name(".trashed-0-a").has_value());
    CHECK_FALSE(parse_trashed_name("trashed-1-a").has_value());
    CHECK_FALSE(parse_trashed_name(".trashed--a").has_value());
    CHECK_FALSE(parse_trashed_name(".trashed-1-").has_value());
    CHECK_FALSE(parse_trashed_name(".trashed-1").has_value());
    CHECK_FALSE(parse_trashed_name(".trashed-abc-a").has_value());
    CHECK_FALSE(parse_trashed_name(".trashed-123456789012345678901-a").has_value());
    CHECK_FALSE(parse_trashed_name("").has_value());
}

TEST_CASE("scan and pull the fake sdcard tree", "[android][bridge]") {
    REQUIRE(fs::is_directory(kFixture));
    test::TempDir out;
    test::TempDir temp;
    test::FakeAdbTransport transport(kFixture);
    AndroidBridge bridge(transport, pull_options(out.path(), temp.path()));

    std::vector<std::pair<uint64_t, uint64_t>> progress;
    auto result = bridge.scan_and_pull(
        kSerial, default_profile(), [&](uint64_t done, uint64_t total) {
            progress.emplace_back(done, total);
            return true;
        });
    REQUIRE(result.has_value());

    CHECK(result->probe.serial == kSerial);
    CHECK(result->probe.model == "Pixel Fake");
    CHECK(result->probe.manufacturer == "Google");
    CHECK(result->probe.release == "14");
    CHECK(result->probe.sdk == 34);
    CHECK(result->probe.crypto_state == "encrypted");
    CHECK(result->limitations.size() == 4);
    CHECK(std::any_of(result->limitations.begin(), result->limitations.end(),
                      [](const std::string& text) {
                          return text.find("scoped_storage_restricts_android_data") != std::string::npos;
                      }));

    REQUIRE(result->roots.size() == 4);
    const AndroidRootResult* cache_root = find_root(*result, "app_media_cache");
    const AndroidRootResult* thumbs_root = find_root(*result, "thumbnails");
    const AndroidRootResult* pics_root = find_root(*result, "thumbnails_pics");
    const AndroidRootResult* trash_root = find_root(*result, "trashed_media");
    REQUIRE(cache_root != nullptr);
    REQUIRE(thumbs_root != nullptr);
    REQUIRE(pics_root != nullptr);
    REQUIRE(trash_root != nullptr);
    CHECK(cache_root->status == "ok");
    CHECK(cache_root->files == 2);
    CHECK(cache_root->pulled == 2);
    CHECK(thumbs_root->files == 3);
    CHECK(thumbs_root->pulled == 3);
    CHECK(pics_root->files == 1);
    CHECK(pics_root->pulled == 1);
    CHECK(trash_root->files == 2);
    CHECK(trash_root->pulled == 2);

    const std::vector<std::string> expected_order = {
        "/sdcard/Android/data/com.denied/cache/secret.jpg",
        "/sdcard/Android/data/com.x/cache/a.png",
        "/sdcard/DCIM/.thumbnails/thumb_corrupt.jpg",
        "/sdcard/DCIM/.thumbnails/thumb_truncated.jpg",
        "/sdcard/DCIM/.thumbnails/thumb_valid.jpg",
        "/sdcard/Pictures/.thumbnails/uni_pic.jpg",
        "/sdcard/DCIM/.trashed-1735689600-IMG_1.jpg",
        "/sdcard/DCIM/.trashed-1735689600-IMG_2.JPG",
    };
    REQUIRE(result->files.size() == expected_order.size());
    for (size_t i = 0; i < expected_order.size(); ++i) {
        CHECK(result->files[i].remote_path == expected_order[i]);
    }

    CHECK(find_file(*result, "/sdcard/Android/data/com.x/files/not_cache.jpg") == nullptr);
    CHECK(find_file(*result, "/sdcard/Android/data/com.x/cache/zero.txt") == nullptr);
    CHECK(find_file(*result, "/sdcard/DCIM/IMG_0001.jpg") == nullptr);

    const AndroidFile* valid_thumb = find_file(*result, "/sdcard/DCIM/.thumbnails/thumb_valid.jpg");
    REQUIRE(valid_thumb != nullptr);
    CHECK(valid_thumb->confidence == Confidence::Medium);
    CHECK(valid_thumb->note == "low-resolution derivative");
    CHECK(valid_thumb->type == "jpeg");
    CHECK(valid_thumb->kind == "thumbnail");
    CHECK(valid_thumb->pulled);
    CHECK(valid_thumb->size_bytes == fs::file_size(fixture_file(valid_thumb->remote_path)));
    CHECK(valid_thumb->sha256 == test::sha256_of_file(fixture_file(valid_thumb->remote_path)));
    CHECK(valid_thumb->local_relative == "android/FAKE1234/thumbnails/thumb_valid.jpg");
    const fs::path valid_out = out.path() / path_from_utf8(valid_thumb->local_relative);
    REQUIRE(fs::is_regular_file(valid_out));
    CHECK(test::sha256_of_file(valid_out) == valid_thumb->sha256);
    CHECK(unix_seconds(fs::last_write_time(valid_out)) == valid_thumb->mtime_unix);

    const AndroidFile* corrupt = find_file(*result, "/sdcard/DCIM/.thumbnails/thumb_corrupt.jpg");
    REQUIRE(corrupt != nullptr);
    CHECK(corrupt->confidence == Confidence::Low);
    CHECK(corrupt->note.find("corrupt") != std::string::npos);

    const AndroidFile* truncated = find_file(*result, "/sdcard/DCIM/.thumbnails/thumb_truncated.jpg");
    REQUIRE(truncated != nullptr);
    CHECK(truncated->confidence == Confidence::Low);
    CHECK(truncated->note.find("truncated") != std::string::npos);

    const AndroidFile* trashed = find_file(*result, "/sdcard/DCIM/.trashed-1735689600-IMG_1.jpg");
    REQUIRE(trashed != nullptr);
    CHECK(trashed->confidence == Confidence::High);
    REQUIRE(trashed->trashed_expires_at.has_value());
    CHECK(*trashed->trashed_expires_at == 1735689600ull);
    CHECK(trashed->kind == "trash");
    CHECK(trashed->local_relative ==
          "android/FAKE1234/trashed_media/DCIM/.trashed-1735689600-IMG_1.jpg");

    const AndroidFile* cache_png = find_file(*result, "/sdcard/Android/data/com.x/cache/a.png");
    REQUIRE(cache_png != nullptr);
    CHECK(cache_png->confidence == Confidence::Medium);
    CHECK(cache_png->type == "png");
    CHECK(cache_png->kind == "cache");
    CHECK(cache_png->local_relative == "android/FAKE1234/app_media_cache/com.x/cache/a.png");

    // Progress counts every candidate that survived enumeration filters, including the
    // zero-length files that are dropped once their stat size is known.
    REQUIRE(progress.size() == 10);
    CHECK(progress.back().first == progress.back().second);
}

TEST_CASE("gif and bmp candidates are validated through the registry", "[android][bridge]") {
    const std::string document = R"({
        "schema": 1,
        "name": "gif_bmp",
        "roots": [{"id": "downloads", "path": "/sdcard/Download", "kind": "cache"}],
        "type_filter": ["gif", "bmp"],
        "max_file_size": 1048576
    })";
    auto profile = parse_scan_profile(document, "test");
    REQUIRE(profile.has_value());

    test::TempDir out;
    test::TempDir temp;
    test::FakeAdbTransport transport(kFixture);
    AndroidBridge bridge(transport, pull_options(out.path(), temp.path()));
    auto result = bridge.scan_and_pull(kSerial, *profile);
    REQUIRE(result.has_value());
    REQUIRE(result->files.size() == 4);

    const AndroidFile* anim = find_file(*result, "/sdcard/Download/anim.gif");
    REQUIRE(anim != nullptr);
    CHECK(anim->type == "gif");
    CHECK(anim->confidence == Confidence::Medium);
    CHECK(anim->pulled);

    const AndroidFile* picture = find_file(*result, "/sdcard/Download/picture.bmp");
    REQUIRE(picture != nullptr);
    CHECK(picture->type == "bmp");
    CHECK(picture->confidence == Confidence::Medium);
    CHECK(picture->pulled);

    const AndroidFile* broken_gif = find_file(*result, "/sdcard/Download/broken.gif");
    REQUIRE(broken_gif != nullptr);
    CHECK(broken_gif->type == "gif");
    CHECK(broken_gif->confidence == Confidence::Low);
    CHECK(broken_gif->note.find("truncated") != std::string::npos);

    const AndroidFile* broken_bmp = find_file(*result, "/sdcard/Download/broken.bmp");
    REQUIRE(broken_bmp != nullptr);
    CHECK(broken_bmp->type == "bmp");
    CHECK(broken_bmp->confidence == Confidence::Low);
    CHECK(broken_bmp->note.find("corrupt") != std::string::npos);
}

TEST_CASE("scan-only writes nothing and reports optimistic confidence", "[android][bridge]") {
    test::TempDir out;
    test::FakeAdbTransport transport(kFixture);
    AndroidBridge bridge(transport, pull_options(out.path(), {}));

    auto result = bridge.scan(kSerial, default_profile());
    REQUIRE(result.has_value());
    REQUIRE(result->files.size() == 8);
    for (const AndroidFile& file : result->files) {
        CHECK_FALSE(file.pulled);
        CHECK(file.local_relative.empty());
        CHECK(file.sha256.empty());
    }
    const AndroidFile* cache_png = find_file(*result, "/sdcard/Android/data/com.x/cache/a.png");
    REQUIRE(cache_png != nullptr);
    CHECK(cache_png->confidence == Confidence::Low);
    CHECK(fs::is_empty(out.path()));
    CHECK(transport.pull_calls() == 0);
}

TEST_CASE("optional denied root is recorded without failing", "[android][bridge]") {
    test::FakeAdbTransport transport(kFixture);
    transport.deny_path("/sdcard/Android/data");
    AndroidBridge bridge(transport, AndroidBridgeOptions{});

    auto result = bridge.scan(kSerial, default_profile());
    REQUIRE(result.has_value());
    const AndroidRootResult* cache_root = find_root(*result, "app_media_cache");
    REQUIRE(cache_root != nullptr);
    CHECK(cache_root->status == "access_denied");
    CHECK(cache_root->files == 0);
    CHECK(cache_root->pulled == 0);
    CHECK(result->files.size() == 6);
}

TEST_CASE("stat access denial splits batches and skips only the denied file", "[android][bridge]") {
    test::FakeAdbTransport transport(kFixture);
    transport.deny_stat_path("/sdcard/Android/data/com.denied/cache/secret.jpg");
    AndroidBridge bridge(transport, AndroidBridgeOptions{});

    auto result = bridge.scan(kSerial, default_profile());
    REQUIRE(result.has_value());
    CHECK(result->files.size() == 7);
    CHECK(find_file(*result, "/sdcard/Android/data/com.denied/cache/secret.jpg") == nullptr);
    CHECK(any_warning_contains(*result, "cannot stat"));
    const AndroidRootResult* cache_root = find_root(*result, "app_media_cache");
    REQUIRE(cache_root != nullptr);
    CHECK(cache_root->files == 1);
}

TEST_CASE("unauthorized and offline devices abort with mapped exit codes", "[android][bridge]") {
    test::FakeAdbTransport transport(kFixture);
    AndroidBridge bridge(transport, AndroidBridgeOptions{});

    transport.set_state(AdbState::Unauthorized);
    auto unauthorized = bridge.scan(kSerial, default_profile());
    REQUIRE_FALSE(unauthorized.has_value());
    CHECK(unauthorized.error().code == ErrorCode::DeviceUnauthorized);
    CHECK(exit_code_for_error(unauthorized.error().code) == 7);

    transport.set_state(AdbState::Offline);
    auto offline = bridge.scan(kSerial, default_profile());
    REQUIRE_FALSE(offline.has_value());
    CHECK(offline.error().code == ErrorCode::DeviceOffline);
    CHECK(exit_code_for_error(offline.error().code) == 1);

    transport.set_state(AdbState::Device);
    transport.remove_device();
    auto missing = bridge.probe(kSerial);
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error().code == ErrorCode::NotFound);
}

TEST_CASE("missing shared storage and shell timeouts surface", "[android][bridge]") {
    test::FakeAdbTransport transport(kFixture);
    AndroidBridge bridge(transport, AndroidBridgeOptions{});

    transport.set_sdcard_present(false);
    auto storage = bridge.probe(kSerial);
    REQUIRE_FALSE(storage.has_value());
    CHECK(storage.error().code == ErrorCode::StorageUnavailable);

    transport.set_sdcard_present(true);
    transport.set_shell_timeout(true);
    auto timeout = bridge.scan(kSerial, default_profile());
    REQUIRE_FALSE(timeout.has_value());
    CHECK(timeout.error().code == ErrorCode::Timeout);
}

TEST_CASE("truncated pulls and progress cancellation are errors", "[android][bridge]") {
    test::TempDir out;
    test::TempDir temp;
    test::FakeAdbTransport transport(kFixture);

    {
        AndroidBridge bridge(transport, pull_options(out.path(), temp.path()));
        transport.set_truncate_pull(true);
        auto result = bridge.scan_and_pull(kSerial, default_profile());
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == ErrorCode::IoError);
        CHECK(result.error().message.find("size mismatch") != std::string::npos);
        transport.set_truncate_pull(false);
    }

    test::TempDir out2;
    test::TempDir temp2;
    AndroidBridge bridge(transport, pull_options(out2.path(), temp2.path()));
    auto cancelled = bridge.scan_and_pull(kSerial, default_profile(),
                                          [](uint64_t, uint64_t) { return false; });
    REQUIRE_FALSE(cancelled.has_value());
    CHECK(cancelled.error().code == ErrorCode::Cancelled);
}

TEST_CASE("a second pull never overwrites the first export", "[android][bridge]") {
    test::TempDir out;
    test::TempDir temp;
    test::FakeAdbTransport transport(kFixture);
    AndroidBridge bridge(transport, pull_options(out.path(), temp.path()));

    auto first = bridge.scan_and_pull(kSerial, default_profile());
    REQUIRE(first.has_value());
    const AndroidFile* first_thumb =
        find_file(*first, "/sdcard/DCIM/.thumbnails/thumb_valid.jpg");
    REQUIRE(first_thumb != nullptr);
    const std::string first_relative = first_thumb->local_relative;

    auto second = bridge.scan_and_pull(kSerial, default_profile());
    REQUIRE(second.has_value());
    const AndroidFile* second_thumb =
        find_file(*second, "/sdcard/DCIM/.thumbnails/thumb_valid.jpg");
    REQUIRE(second_thumb != nullptr);
    CHECK(second_thumb->local_relative != first_relative);
    CHECK(second_thumb->local_relative.find(" (1)") != std::string::npos);
    CHECK(fs::is_regular_file(out.path() / path_from_utf8(first_relative)));
    CHECK(fs::is_regular_file(out.path() / path_from_utf8(second_thumb->local_relative)));
    CHECK(test::sha256_of_file(out.path() / path_from_utf8(first_relative)) ==
          test::sha256_of_file(fixture_file(first_thumb->remote_path)));
}

TEST_CASE("custom profiles filter by type, size and root", "[android][bridge]") {
    test::TempDir out;
    test::TempDir temp;
    test::FakeAdbTransport transport(kFixture);
    AndroidBridge bridge(transport, pull_options(out.path(), temp.path()));

    auto pdf_profile = parse_scan_profile(
        R"({"schema":1,"name":"pdf_only","roots":[{"id":"downloads","path":"/sdcard/Download","kind":"thumbnail"}],"type_filter":["pdf"],"max_file_size":1000000})",
        "test");
    REQUIRE(pdf_profile.has_value());
    auto result = bridge.scan_and_pull(kSerial, *pdf_profile);
    REQUIRE(result.has_value());
    REQUIRE(result->files.size() == 1);
    CHECK(result->files[0].remote_path == "/sdcard/Download/report.pdf");
    CHECK(result->files[0].confidence == Confidence::Medium);
    CHECK(result->files[0].pulled);

    auto tiny_profile = parse_scan_profile(
        R"({"schema":1,"name":"tiny","roots":[{"id":"downloads","path":"/sdcard/Download","kind":"thumbnail"}],"type_filter":["pdf","zip"],"max_file_size":100})",
        "test");
    REQUIRE(tiny_profile.has_value());
    test::TempDir out2;
    AndroidBridge bridge2(transport, pull_options(out2.path(), temp.path()));
    auto skipped = bridge2.scan(kSerial, *tiny_profile);
    REQUIRE(skipped.has_value());
    CHECK(skipped->files.empty());
    CHECK(any_warning_contains(*skipped, "max_file_size"));
}

TEST_CASE("validation can be disabled", "[android][bridge]") {
    test::TempDir out;
    test::TempDir temp;
    test::FakeAdbTransport transport(kFixture);
    AndroidBridgeOptions options = pull_options(out.path(), temp.path());
    options.validate_media = false;
    AndroidBridge bridge(transport, options);

    auto result = bridge.scan_and_pull(kSerial, default_profile());
    REQUIRE(result.has_value());
    const AndroidFile* cache_png = find_file(*result, "/sdcard/Android/data/com.x/cache/a.png");
    REQUIRE(cache_png != nullptr);
    CHECK(cache_png->confidence == Confidence::Low);
}

TEST_CASE("scoped storage limitation depends on sdk", "[android][bridge]") {
    CHECK(android_limitations(29).size() == 3);
    CHECK(android_limitations(30).size() == 4);
    CHECK(android_limitations(34).size() == 4);
    CHECK(android_limitations(0).size() == 3);

    test::FakeAdbTransport transport(kFixture);
    transport.set_property("ro.build.version.sdk", "29");
    AndroidBridge bridge(transport, AndroidBridgeOptions{});
    auto probe = bridge.probe(kSerial);
    REQUIRE(probe.has_value());
    CHECK(probe->sdk == 29);
}

TEST_CASE("exit codes follow the specification table", "[android][error]") {
    CHECK(exit_code_for_error(ErrorCode::IoError) == 1);
    CHECK(exit_code_for_error(ErrorCode::NotFound) == 1);
    CHECK(exit_code_for_error(ErrorCode::Timeout) == 1);
    CHECK(exit_code_for_error(ErrorCode::InvalidArgument) == 2);
    CHECK(exit_code_for_error(ErrorCode::PolicyViolation) == 2);
    CHECK(exit_code_for_error(ErrorCode::PermissionDenied) == 3);
    CHECK(exit_code_for_error(ErrorCode::AccessDenied) == 3);
    CHECK(exit_code_for_error(ErrorCode::DeviceBusy) == 4);
    CHECK(exit_code_for_error(ErrorCode::Unsupported) == 5);
    CHECK(exit_code_for_error(ErrorCode::NoFilesystem) == 5);
    CHECK(exit_code_for_error(ErrorCode::OutputOnSourceDevice) == 6);
    CHECK(exit_code_for_error(ErrorCode::DeviceUnauthorized) == 7);
}
