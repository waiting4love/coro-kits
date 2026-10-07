// Implementation of sqlite.hpp. All sqlite3_* calls live in this file; the
// rest of the codebase only needs the forward declarations in sqlite.hpp to
// hold handle pointers.
#include "sqlite.hpp"

#include <cstdio>
#include <utility>

#include <sqlite3.h>

namespace sqlite {
namespace {

// Single throw point: a constraint violation (primary code
// SQLITE_CONSTRAINT) throws ConstraintError, everything else Error.
// Message format follows the established convention: "[sqlite] what: errmsg"
[[noreturn]] void fail(const std::string& what, int rc, const std::string& msg) {
    if ((rc & 0xff) == SQLITE_CONSTRAINT) // NOLINT(bugprone-signed-bitwise)
        throw ConstraintError(what, rc, msg);
    throw Error(what, rc, msg);
}

// Pops the newest errmsg from the connection, then throws
[[noreturn]] void failDb(const std::string& what, sqlite3* db, int rc) {
    const char* msg = db != nullptr ? sqlite3_errmsg(db) : sqlite3_errstr(rc);
    fail(what, rc, msg != nullptr ? msg : "unknown error");
}

// Default open flags, equivalent to plain sqlite3_open; sqlite flags are
// signed ints and bitwise-or is their documented use - the exemption is
// concentrated on this one line
constexpr int kOpenDefault = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE; // NOLINT(bugprone-signed-bitwise)

} // namespace

// ---- error ----

Error::Error(const std::string& what, int rc, const std::string& msg)
    : std::runtime_error("[sqlite] " + what + ": " + msg), rc_(rc) {}

ConstraintError::ConstraintError(const std::string& what, int rc, const std::string& msg)
    : Error(what, rc, msg) {}

// ---- prepared statement ----

Statement::Statement(sqlite3* db, const std::string& sql) : db_(db) {
    if (db == nullptr)
        fail("prepare failed", SQLITE_MISUSE, "db not open");
    if (sqlite3_prepare_v2(db, sql.data(), (int)sql.size(), &stmt_, nullptr) != SQLITE_OK) {
        stmt_ = nullptr; // sqlite guarantees *ppStmt is NULL on failure; set it explicitly anyway
        failDb("prepare failed", db, sqlite3_errcode(db));
    }
}

Statement::~Statement() {
    if (stmt_ != nullptr)
        sqlite3_finalize(stmt_);
}

Statement::Statement(Statement&& other) noexcept
    : db_(std::exchange(other.db_, nullptr)), stmt_(std::exchange(other.stmt_, nullptr)),
      stepped_(std::exchange(other.stepped_, false)) {}

Statement& Statement::operator=(Statement&& other) noexcept {
    if (this != &other) {
        if (stmt_ != nullptr)
            sqlite3_finalize(stmt_);
        db_ = std::exchange(other.db_, nullptr);
        stmt_ = std::exchange(other.stmt_, nullptr);
        stepped_ = std::exchange(other.stepped_, false);
    }
    return *this;
}

void Statement::beforeBind() {
    if (stepped_) // a previous iteration was left unfinished; must reset before rebinding
        reset();
}

void Statement::checkBind(int rc, const char* what) const {
    if (rc != SQLITE_OK)
        failDb(what, db_, rc);
}

Statement& Statement::bindInt(int idx, long long v) {
    beforeBind();
    checkBind(sqlite3_bind_int64(stmt_, idx, v), "bind int");
    return *this;
}

Statement& Statement::bindText(int idx, const char* p, int n) {
    beforeBind();
    // SQLITE_TRANSIENT: sqlite copies immediately, so temporary strings from
    // the caller are safe
    checkBind(sqlite3_bind_text(stmt_, idx, p, n, SQLITE_TRANSIENT), "bind text");
    return *this;
}

Statement& Statement::bindNull(int idx) {
    beforeBind();
    checkBind(sqlite3_bind_null(stmt_, idx), "bind null");
    return *this;
}

Statement& Statement::bind(int idx, std::nullptr_t) { return bindNull(idx); }

Statement& Statement::bind(int idx, double v) {
    beforeBind();
    checkBind(sqlite3_bind_double(stmt_, idx, v), "bind double");
    return *this;
}

Statement& Statement::bind(int idx, const char* v) {
    return v != nullptr ? bindText(idx, v, -1) : bindNull(idx);
}

Statement& Statement::bind(int idx, const std::string& v) {
    return bindText(idx, v.data(), (int)v.size());
}

bool Statement::step() {
    const int rc = sqlite3_step(stmt_);
    if (rc == SQLITE_ROW) {
        stepped_ = true;
        return true;
    }
    reset(); // DONE resets normally; error paths reset first too (prepare_v2 semantics auto-reset), then throw
    if (rc != SQLITE_DONE)
        failDb("step failed", db_, rc);
    return false;
}

long long Statement::run() {
    const int rc = sqlite3_step(stmt_);
    reset(); // affected rows come from the connection counter; resetting first is fine
    if (rc != SQLITE_DONE)
        failDb("step failed", db_, rc);
    return db_ != nullptr ? sqlite3_changes64(db_) : 0;
}

void Statement::reset() noexcept {
    if (stmt_ == nullptr)
        return;
    sqlite3_reset(stmt_);          // its return code repeats the last step's error, already reported in step/run
    sqlite3_clear_bindings(stmt_); // a reset means a full rebind: no stale parameters survive
    stepped_ = false;
}

int Statement::columnCount() const noexcept { return sqlite3_column_count(stmt_); }
bool Statement::isNull(int col) const noexcept { return sqlite3_column_type(stmt_, col) == SQLITE_NULL; }
long long Statement::integer(int col) const noexcept { return sqlite3_column_int64(stmt_, col); }
double Statement::real(int col) const noexcept { return sqlite3_column_double(stmt_, col); }

std::string Statement::text(int col) const {
    const unsigned char* p = sqlite3_column_text(stmt_, col);
    if (p == nullptr)
        return {}; // NULL column (or OOM) -> empty string, per the colText convention
    // column_bytes must be called after column_text (convert first, then measure); tolerates inner \0
    return { reinterpret_cast<const char*>(p), static_cast<size_t>(sqlite3_column_bytes(stmt_, col)) };
}

// ---- connection ----

Db::Db(const std::string& path) { open(path, kOpenDefault); }
Db::Db(const std::string& path, int flags) { open(path, flags); }
Db::~Db() { close(); }

Db::Db(Db&& other) noexcept : db_(std::exchange(other.db_, nullptr)) {}

Db& Db::operator=(Db&& other) noexcept {
    if (this != &other) {
        close();
        db_ = std::exchange(other.db_, nullptr);
    }
    return *this;
}

void Db::open(const std::string& path) { open(path, kOpenDefault); }

void Db::open(const std::string& path, int flags) {
    close();
    sqlite3* h = nullptr;
    const int rc = sqlite3_open_v2(path.c_str(), &h, flags, nullptr);
    if (rc != SQLITE_OK) {
        const std::string msg = h != nullptr ? sqlite3_errmsg(h) : sqlite3_errstr(rc);
        const int code = h != nullptr ? sqlite3_errcode(h) : rc;
        if (h != nullptr)
            sqlite3_close_v2(h); // release the half-open handle
        fail("open failed ('" + path + "')", code, msg);
    }
    db_ = h;
    // Enable extended result codes: later step/prepare failures carry the
    // extension bits (e.g. SQLITE_CONSTRAINT_UNIQUE=2067 instead of bare
    // SQLITE_CONSTRAINT=19), so Error::code() can tell UNIQUE/FK/NOT NULL
    // apart
    sqlite3_extended_result_codes(db_, 1);
}

void Db::close() noexcept {
    if (db_ == nullptr)
        return;
    // close_v2 tolerates unfinalized Statements: the connection turns into a
    // zombie and is truly released when the last statement dies. Either
    // member order ("Statement first, Db last" or the reverse) is therefore
    // safe in a store (sqlite3_close would just return SQLITE_BUSY and leak)
    sqlite3_close_v2(db_);
    db_ = nullptr;
}

void Db::exec(const std::string& sql) {
    if (db_ == nullptr)
        fail("exec failed", SQLITE_MISUSE, "db not open");
    char* err = nullptr;
    const int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        // prefer the errmsg buffer: for multi-statement scripts it points at the failure ("near X: ...")
        const std::string msg = err != nullptr ? err : sqlite3_errmsg(db_);
        sqlite3_free(err);
        fail("exec failed", rc, msg);
    }
}

Statement Db::prepare(const std::string& sql) {
    if (db_ == nullptr)
        fail("prepare failed", SQLITE_MISUSE, "db not open");
    return {db_, sql};
}

long long Db::changes() const noexcept { return db_ != nullptr ? sqlite3_changes64(db_) : 0; }
long long Db::lastInsertRowid() const noexcept {
    return db_ != nullptr ? sqlite3_last_insert_rowid(db_) : 0;
}
bool Db::autocommit() const noexcept { return db_ == nullptr || sqlite3_get_autocommit(db_) != 0; }

Transaction Db::begin(Transaction::Mode mode) { return Transaction(*this, mode); }

// ---- transaction ----

Transaction::Transaction(Db& db, Mode mode) : db_(db.handle()) {
    const char* begin = "BEGIN";
    if (mode == Mode::immediate)
        begin = "BEGIN IMMEDIATE";
    else if (mode == Mode::exclusive)
        begin = "BEGIN EXCLUSIVE";
    if (sqlite3_exec(db_, begin, nullptr, nullptr, nullptr) != SQLITE_OK)
        failDb("begin transaction failed", db_, sqlite3_errcode(db_));
}

Transaction::~Transaction() {
    // No rollback when:
    //  - commit/rollback was explicit (finished_)
    //  - this is a moved-from empty source (db_ is null)
    //  - sqlite already auto-rolled back after a severe error and autocommit
    //    is back on - skipping avoids a spurious "no transaction is active"
    // Otherwise the commit never happened -> ROLLBACK, honoring the
    // destructor contract. Destructors must not throw: a failed ROLLBACK
    // only reports to stderr (in practice only when the connection is broken)
    if (db_ == nullptr || finished_ || sqlite3_get_autocommit(db_) != 0)
        return;
    char* err = nullptr;
    if (sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, &err) != SQLITE_OK && err != nullptr)
        std::fprintf(stderr, "[sqlite] rollback on transaction destruction failed: %s\n", err);
    sqlite3_free(err);
}

Transaction::Transaction(Transaction&& other) noexcept
    : db_(std::exchange(other.db_, nullptr)), finished_(std::exchange(other.finished_, true)) {}

void Transaction::ensureActive(const char* what) const {
    if (db_ == nullptr || finished_)
        fail(what, SQLITE_MISUSE, "transaction already finished");
}

void Transaction::commit() {
    ensureActive("commit");
    // On failure (e.g. SQLITE_BUSY) finished_ stays false, the transaction
    // remains active and the destructor attempts rollback - i.e. "a commit
    // that did not succeed gets rolled back"
    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK)
        failDb("commit failed", db_, sqlite3_errcode(db_));
    finished_ = true;
}

void Transaction::rollback() {
    ensureActive("rollback");
    if (sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr) != SQLITE_OK)
        failDb("rollback failed", db_, sqlite3_errcode(db_));
    finished_ = true;
}

} // namespace sqlite
