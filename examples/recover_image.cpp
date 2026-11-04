// Recover deleted files from a disk image using only the public OpenRecover API.
//
//   example_recover_image <image> <output-dir>
//
// Three library calls do the work: `open_volume` opens the source read-only and picks the volume to
// work on, `export_metadata` writes back every file the filesystem still names, and
// `carve_and_export` recovers what the metadata lost by matching signatures. The example only decides
// where the bytes go and how to show them: `OutputSink` is the one writer in the whole pipeline, and
// the source is never touched.

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "openrecover/openrecover.hpp"

namespace {

using namespace openrecover;

[[noreturn]] int abort_with(const Error& error) {
    std::fprintf(stderr, "openrecover: %s\n", error.to_string().c_str());
    std::exit(exit_code_for_error(error.code));
}

// Prints one line per whole percentage so the example stays readable without a TTY library.
ProgressFn text_progress(const char* stage) {
    uint64_t last = UINT64_MAX;
    return [stage, last](uint64_t done, uint64_t total) mutable {
        const uint64_t percent = total > 0 ? done * 100 / total : 100;
        if (percent != last) {
            std::fprintf(stderr, "%s: %llu%%\n", stage, static_cast<unsigned long long>(percent));
            last = percent;
        }
        return true;
    };
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <image> <output-dir>\n", argv[0]);
        return 2;
    }
    const std::string source = argv[1];
    const std::filesystem::path output = argv[2];

    // A source whose filesystem is gone is still full of bytes worth carving, so the volume is
    // opened without demanding a scanner; `scanner()` being null then just skips the metadata phase.
    SourceRequest request;
    request.source = source;
    auto opened = open_volume(request, false);
    if (!opened) abort_with(opened.error());

    auto sink = io::OutputSink::open(output, io::SourceIdentity::from_source_string(source));
    if (!sink) abort_with(sink.error());

    // The defaults recover everything: no confidence floor, no type list, no size cap.
    ExportFilter filter;

    CarveRequest carving;
    // Ask for the free space and let the library fall back to scanning the whole volume when the
    // filesystem cannot say what is free.
    carving.options.scope = carve::CarveOptions::Scope::UnallocatedOnly;
    // Deleted files rarely begin on a cluster boundary once the allocator has moved on.
    carving.options.unaligned = true;
    // A signature alone is a coincidence candidate; validating the container keeps the junk out.
    carving.options.deep_validate = true;
    // A head cut by later writes is not the whole file: the walk rejoins the pieces it can prove
    // belong to it and keeps the chain only when it ends at the format's terminator.
    carving.options.reassemble = true;

    report::Report document = opened->base_report();
    std::vector<RecoveredFile> accepted;
    const bool have_metadata = opened->scanner() != nullptr;

    if (have_metadata) {
        auto exported = export_metadata(*opened, **sink, filter, text_progress("metadata"), document,
                                        &accepted);
        if (!exported) abort_with(exported.error());
    }

    // Handing the metadata results to the carve lets the engine mark a carved copy of a file that
    // already came back by name as a duplicate instead of writing it twice.
    auto carved = carve_and_export(*opened, **sink, carving, filter, text_progress("carve"), document,
                                   have_metadata ? &accepted : nullptr);
    if (!carved) abort_with(carved.error());

    report::finalize(document);
    auto wrote = report::write_to_sink(**sink, document, "report.json", "manifest.csv");
    if (!wrote) abort_with(wrote.error());

    std::printf("%s\n", report::to_json(document).c_str());
    return 0;
}
