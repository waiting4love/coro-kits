#pragma once
// HTTP business error: thrown by handlers, converted to a JSON response by
// the central error handler (mirrors Koa's err.status / err.expose semantics).

#include <stdexcept>
#include <string>
#include <utility>

struct HttpError : std::runtime_error {
    int status;   // HTTP status code
    bool expose;  // true: message goes to the client; false: "Internal error"

    HttpError(int status_, const std::string& msg, bool expose_ = true)
        : std::runtime_error(msg), status(status_), expose(expose_) {}
};

// Convenience throw (expose defaults to true)
[[noreturn]] inline void throwHttp(int status, const std::string& msg, bool expose = true) {
    throw HttpError(status, msg, expose);
}
