#pragma once
// Thin RAII wrapper over the SQLite C API.
//
// Designed around store-layer usage patterns: a single-threaded
// io_context with one connection and no locks; statements prepared once and
// reused; text bound with SQLITE_TRANSIENT; errors thrown as exceptions.
//
// Three classes:
//   sqlite::Db           connection (sqlite3*): open/exec/prepare/changes/begin,
//                        closed automatically on destruction
//   sqlite::Statement    prepared statement (sqlite3_stmt*): bind/step/run +
//                        column access, finalized automatically on destruction
//   sqlite::Transaction  transaction: BEGIN on construction; destruction
//                        without an explicit commit() -> automatic ROLLBACK
//
// Conventions:
//   - bind parameter indices start at 1 (as in sqlite itself)
//   - errors throw sqlite::Error; constraint violations (UNIQUE/FK/CHECK/
//     NOT NULL) throw the subclass sqlite::ConstraintError (map to HTTP 409
//     if that fits your API)
//   - a NULL text column reads back as an empty string (use isNull to tell
//     them apart)
//   - Statement/Transaction must not outlive their Db (member declaration
//     order in the store guarantees this)

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

// Official opaque handle types, forward-declared: this header pulls in no C
// headers; <sqlite3.h> is only included in sqlite.cpp (heavy headers must
// not leak into the whole project)
struct sqlite3;
struct sqlite3_stmt;

namespace sqlite {

// ---- error ----

class Error : public std::runtime_error {
public:
    // what like "step failed"; msg is sqlite3_errmsg / sqlite3_exec errmsg
    Error(const std::string& what, int rc, const std::string& msg);
    [[nodiscard]] int code() const noexcept { return rc_; } // raw (extended) error code
    // primary code = low 8 bits (SQLITE_CONSTRAINT for any constraint
    // violation); sqlite error codes are signed ints and bitmasking them is
    // the C API idiom
    [[nodiscard]] int primaryCode() const noexcept { return rc_ & 0xff; } // NOLINT(bugprone-signed-bitwise)
private:
    int rc_;
};

// Constraint violation (UNIQUE / foreign key / CHECK / NOT NULL ...)
class ConstraintError : public Error {
public:
    ConstraintError(const std::string& what, int rc, const std::string& msg);
};

// ---- prepared statement ----

class Statement {
public:
    Statement() = default;
    // Usually obtained via Db::prepare(); throws Error on compile failure
    Statement(sqlite3* db, const std::string& sql);
    ~Statement();
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    Statement(Statement&& other) noexcept;
    Statement& operator=(Statement&& other) noexcept;

    [[nodiscard]] sqlite3_stmt* handle() const noexcept { return stmt_; }

    // Binding (parameter indices start at 1; chainable). An empty optional /
    // nullptr binds NULL
    Statement& bind(int idx, std::nullptr_t);
    // Integers share one constrained template: on LP64 platforms int64_t is
    // long, and separate int/long long overloads would make a long argument
    // ambiguous between int/long long/double standard conversions; the
    // template is an exact match for every integral type (int64_t/size_t/
    // long...). bool/enum are rejected (cast explicitly first)
    template <std::integral T>
        requires (!std::same_as<T, bool>)
    Statement& bind(int idx, T v) { return bindInt(idx, static_cast<long long>(v)); }
    Statement& bind(int idx, double v);
    Statement& bind(int idx, const char* v); // nullptr binds NULL
    Statement& bind(int idx, const std::string& v);
    // optionals delegate to the matching bind; an empty one binds NULL
    template <typename T>
    Statement& bind(int idx, const std::optional<T>& v) {
        return v.has_value() ? bind(idx, *v) : bindNull(idx);
    }

    // Advances one row. true = SQLITE_ROW (columns of the current row are
    // readable); false = SQLITE_DONE, the statement has been reset and
    // parameters cleared, ready to bind again. Any other code throws Error
    // (the statement is reset before throwing, so it stays reusable)
    bool step();

    // Write statement in one step: runs to DONE, resets, returns affected
    // rows (sqlite3_changes64). Throws Error if misused on a statement that
    // produces rows
    long long run();

    // Manual reset (sqlite3_reset + sqlite3_clear_bindings). bind() auto-
    // resets when a previous iteration was left unfinished; normally no
    // explicit call is needed. After step() returns false / run(), the
    // statement is always already reset
    void reset() noexcept;

    // ---- column access (valid only on the current row after step() returned true) ----
    [[nodiscard]] int columnCount() const noexcept;
    [[nodiscard]] bool isNull(int col) const noexcept;
    [[nodiscard]] long long integer(int col) const noexcept; // NULL column reads 0 (sqlite semantics)
    [[nodiscard]] double real(int col) const noexcept;
    [[nodiscard]] std::string text(int col) const; // NULL column reads ""; sliced by column_bytes, tolerates inner \0

private:
    void beforeBind(); // reset first if a previous iteration is unfinished (sqlite would return MISUSE)
    void checkBind(int rc, const char* what) const;
    Statement& bindInt(int idx, long long v);
    Statement& bindText(int idx, const char* p, int n); // n<0 means NUL-terminated
    Statement& bindNull(int idx);

    sqlite3* db_ = nullptr; // owning connection, only for error messages (non-owning)
    sqlite3_stmt* stmt_ = nullptr;
    bool stepped_ = false;  // stepped to a row and not reset yet; the next bind auto-resets
};

class Db;

// ---- transaction ----
//
// Usage:
//   sqlite::Transaction tx = db.begin();
//   ...db.prepare(...)->bind(...)->run()...
//   tx.commit();  // leaving scope without calling it -> destructor ROLLBACKs;
//                 // an exception mid-way unwinds into the same rollback
class Transaction {
public:
    enum class Mode : std::uint8_t { deferred, immediate, exclusive }; // BEGIN / BEGIN IMMEDIATE / BEGIN EXCLUSIVE

    // throws Error if BEGIN fails (e.g. nested begin)
    explicit Transaction(Db& db, Mode mode = Mode::deferred);
    // ROLLBACK unless commit()/rollback() was called. The destructor does
    // not throw; a failed rollback only reports to stderr
    ~Transaction();
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    Transaction(Transaction&& other) noexcept; // a moved-from source destructs as a no-op

    // Commit. On failure (e.g. SQLITE_BUSY) throws Error, the transaction
    // stays active and the later destructor attempts rollback - i.e. "a
    // commit that did not succeed gets rolled back"
    void commit();
    // Explicit rollback (throws Error on failure); same as destructor
    // rollback but error-visible
    void rollback();

private:
    void ensureActive(const char* what) const;

    sqlite3* db_ = nullptr; // non-owning; must not outlive its Db
    bool finished_ = false; // commit/rollback done (also true for a moved-from empty source)
};

// ---- connection ----

class Db {
public:
    Db() = default;
    // READWRITE|CREATE by default, matching plain sqlite3_open; use the
    // flags overload for anything else
    explicit Db(const std::string& path);
    Db(const std::string& path, int flags);
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;
    Db(Db&& other) noexcept;
    Db& operator=(Db&& other) noexcept;

    // Does not create parent directories; call
    // std::filesystem::create_directories(parent_path) first if needed
    void open(const std::string& path);
    void open(const std::string& path, int flags);
    void close() noexcept; // idempotent
    [[nodiscard]] sqlite3* handle() const noexcept { return db_; }
    explicit operator bool() const noexcept { return db_ != nullptr; }

    // Runs no-parameter SQL (DDL / PRAGMA / multi-statement scripts); throws Error on failure
    void exec(const std::string& sql);

    // Compiles a fresh statement each time; hot paths should prepare once in
    // the store constructor and keep the member for reuse
    Statement prepare(const std::string& sql);

    [[nodiscard]] long long changes() const noexcept;         // rows affected by the last write
    [[nodiscard]] long long lastInsertRowid() const noexcept; // rowid of the last INSERT
    [[nodiscard]] bool autocommit() const noexcept;           // true = no transaction active

    Transaction begin(Transaction::Mode mode = Transaction::Mode::deferred);

private:
    sqlite3* db_ = nullptr;
};

} // namespace sqlite
