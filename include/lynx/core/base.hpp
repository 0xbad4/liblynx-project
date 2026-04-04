#pragma once

#include "error.hpp"
#include "constants.hpp"
#include "utils.hpp"
#include "common.hpp"
#include "lynx/config.hpp"
// WARN: NEVER INCLUDE proto_base.hpp here, circular include


//  BaseObject
//
//  inherited by Interface, Packet, Buffer, and all protocol layers.
//  carries the last error state. first-error-wins policy means you can
//  chain calls and check ok() once at the end — the root cause is preserved.

namespace lynx {

    class BaseObject {
        public:
        
            [[nodiscard]] bool         ok()     const noexcept { return err_.ok(); }
            [[nodiscard]] Status       status() const noexcept { return err_.type; }
            [[nodiscard]] const char*  errmsg() const noexcept { return err_.what(); }
            [[nodiscard]] const Error& error()  const noexcept { return err_; }
        
            // clears error state so the object can be reused.
            // call explicitly after handling an error — never called automatically.
            void clear_error() noexcept { err_.clear(); }
        
        protected:
            // first-error-wins: silently ignored if an error is already recorded.
            void set_error(Status s, const char* msg) noexcept {
                if (err_.type != Status::Ok) return;
                err_.type = s;
                err_.msg  = msg;
            }
        
            // convenience overload — sets from an Error value directly.
            void absorb(const Error& e) noexcept {
                if (!e.ok()) set_error(e.type, e.msg);
            }
        
            // force-overwrite — use only when you explicitly want to replace
            // a stale error (e.g. after clear_error() + retry).
            void overwrite_error(Status s, const char* msg) noexcept {
                err_.type = s;
                err_.msg  = msg;
            }
        
        private:
            Error err_;
    };

} // namespace lynx
