// Emits the shared read-only policy consumed by tools/adb_sidecar/policy.py and
// sidecar.py. Built and run by CMake so the Python side never drifts from C++.
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "openrecover/android/adb_command_policy.hpp"

namespace {

using namespace openrecover::android;

nlohmann::ordered_json build_policy() {
    nlohmann::ordered_json policy;
    policy["schema"] = 1;
    policy["proto"] = 1;
    policy["max_remote_path_bytes"] = kMaxRemotePathBytes;
    policy["max_prop_key_bytes"] = 64;
    policy["max_serial_bytes"] = 128;
    policy["max_stat_files"] = kMaxStatFiles;
    policy["sd_card_regex"] = "^/storage/[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}(?:/|$)";
    policy["forbidden_remote_path_chars"] = std::string(kForbiddenRemotePathChars);
    policy["stat_format"] = std::string(kStatFormat);
    policy["testdir_probe_yes"] = "openrecover:yes";
    policy["testdir_probe_no"] = "openrecover:no";
    policy["denied_verbs"] = denied_adb_verbs();
    policy["allowed_ops"] = std::vector<std::string>{"list_devices", "shell", "pull"};
    policy["shell_kinds"] = std::vector<std::string>{"GetProp", "ListFiles", "StatBatch", "TestDir"};

    // Shared with the C++/Python parity test: all 20 must be rejected by both sides.
    policy["malicious_remote_paths"] = std::vector<std::string>{
        "/sdcard/../data",
        "/sdcard/DCIM/../../sdcard",
        "/data/media",
        "/dev/block/mmcblk0",
        "/system/etc/hosts",
        "/sdcard/DCIM/'; rm -rf /sdcard #",
        "/sdcard/$HOME",
        "/sdcard/a;b",
        "/sdcard/a|b",
        "/sdcard/a&b",
        "/sdcard/`id`",
        std::string("/sdcard/a\nb"),
        "/sdcard/a\\b",
        "/sdcard/DCIM/",
        "/sdcard//DCIM",
        "/mnt/sdcard/DCIM",
        "/storage/emulated/1/DCIM",
        "/storage/abcd-efgh/x",
        "relative/sdcard/x",
        std::string("/sdcard/") + std::string(5000, 'a'),
    };
    policy["accepted_remote_path_samples"] = std::vector<std::string>{
        "/sdcard",
        "/sdcard/DCIM",
        "/sdcard/DCIM/photo 1.jpg",
        "/sdcard/DCIM/O'Brien.jpg",
        "/sdcard/Photos/\xE7\x85\xA7\xE7\x89\x87.png",
        "/storage/emulated/0/Android/data/com.example/cache/a.png",
        "/storage/ABCD-1234/Music/track.mp3",
    };
    return policy;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 2) {
        std::cerr << "usage: adb_policy_dump [output.json]\n";
        return 2;
    }
    const nlohmann::ordered_json policy = build_policy();
    if (argc == 2) {
        std::ofstream out(argv[1], std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "adb_policy_dump: cannot open " << argv[1] << "\n";
            return 1;
        }
        out << policy.dump(2) << "\n";
        if (!out) {
            std::cerr << "adb_policy_dump: write failed for " << argv[1] << "\n";
            return 1;
        }
        return 0;
    }
    std::cout << policy.dump(2) << "\n";
    return 0;
}
