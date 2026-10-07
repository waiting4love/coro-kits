#pragma once
// Framework-level HTTP config (business-agnostic): the framework only knows
// the fields in this file. Host/port/db paths and other deployment config
// live in the application's own Config, which embeds this struct (defaults
// are the app's to choose) and passes it to the framework after assembly.

#include <string>
#include <vector>

struct HttpConfig {
    // Second-level path the service is mounted under (a gateway dispatches
    // by path); empty = served at the root. An exact hit -> 302 to the
    // trailing-slash form (friendly to SPA relative paths)
    std::string basePath;

    // Static asset directory (contains the SPA fallback index.html);
    // empty = no static serving
    std::string staticDir;

    // SPA fallback exclusion prefixes: unmatched paths under these prefixes
    // get a 404 JSON and never fall back to index.html (filled in by the
    // application layer; no framework default)
    std::vector<std::string> spaExcludePrefixes;

    // ---- CORS policy ----
    // A non-empty origin enables it: every response carries these three
    // headers (405/parse errors/413 included - otherwise cross-origin
    // browsers only see a TypeError instead of the real status); an OPTIONS
    // preflight on any path short-circuits to 204 + these headers + Max-Age
    std::string corsAllowOrigin;
    std::string corsAllowMethods;
    std::string corsAllowHeaders;
};
