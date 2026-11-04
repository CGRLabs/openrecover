#pragma once

// Umbrella header for consumers of the OpenRecover library. Including this gets the stable,
// read-only recovery surface: open a source, detect and scan a filesystem, carve by signature,
// export through the single OutputSink, and read the structured report.
//
// Deliberately absent: the per-format signature classes, the per-filesystem scanners and their
// metadata parsers, and the platform device backends. Those headers exist and are usable, but
// they are the library's internals; a consumer that needs them includes them directly and takes
// the churn.

#include "openrecover/carve/carve_engine.hpp"
#include "openrecover/carve/signature.hpp"
#include "openrecover/common/error.hpp"
#include "openrecover/common/log.hpp"
#include "openrecover/common/readonly.hpp"
#include "openrecover/common/result.hpp"
#include "openrecover/common/types.hpp"
#include "openrecover/fs/allocation_map.hpp"
#include "openrecover/fs/filesystem.hpp"
#include "openrecover/io/block_device.hpp"
#include "openrecover/io/image_device.hpp"
#include "openrecover/io/output_sink.hpp"
#include "openrecover/io/partition_view.hpp"
#include "openrecover/partition/partition_scanner.hpp"
#include "openrecover/recover.hpp"
#include "openrecover/report/report.hpp"
