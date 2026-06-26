#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Algorithm / cipher detection for Ghidra pseudocode output.
//
// Each detection is a self-contained function registered in the kDetectors[]
// table in algo_detector.cpp.  To add a detection: write a static function
// that appends to hits, then add it to the table.  To disable one: comment
// it out of the table.  No other file needs changing.
// ---------------------------------------------------------------------------

struct AlgoHit {
    std::string name;   // human-readable label used in the comment
};

// Scan pseudocode C text and return all detected algorithm matches.
// Duplicates (same name) are suppressed.
std::vector<AlgoHit> detect_algorithms(const std::string& pseudocode);

// Prepend one "// detected - NAME (detection may be wrong)" line per hit
// to the pseudocode.  Returns the original string unchanged if nothing fired.
std::string annotate_algorithms(const std::string& pseudocode);
