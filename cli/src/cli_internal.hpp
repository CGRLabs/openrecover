#pragma once

#include <memory>
#include <string>

#include "cli_common.hpp"
#include "openrecover/io/output_sink.hpp"
#include "openrecover/report/report.hpp"

namespace openrecover::cli {

struct ReportDestination {
    std::unique_ptr<io::OutputSink> sink;
    std::string report_relative;
    std::string manifest_relative;
};

// Opens the only output sink used by a command. When `out_dir` is non-empty the sink root
// is that directory and --report (if any) must stay inside it. When `out_dir` is empty, the
// sink is empty too unless --report is given, in which case the report's parent is the root.
Result<ReportDestination> open_report_destination(const GlobalOptions& global,
                                                  const std::string& source,
                                                  const std::string& out_dir,
                                                  bool default_report);

Result<void> write_report_destination(const ReportDestination& destination,
                                      const report::Report& report);

ProgressFn make_progress(const GlobalOptions& global, std::string label);

}  // namespace openrecover::cli
