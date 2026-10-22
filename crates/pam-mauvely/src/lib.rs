//! `pam_mauvely`: signing in to Mauvely OS with a Mauvely account (brief 26).
//!
//! The module asks `mauvelyd` and nothing else, over `/run/mauvely/auth.sock`
//! (`client`). It opens no file, touches no network, starts no thread, and
//! fails closed and fast when the daemon is missing or silent. What it does
//! with each answer is `flow`; this file is the FFI around it.
//!
//! - `pam_sm_authenticate`: the password through `pam_get_authtok`, so an
//!   earlier module's is used and it stays in `PAM_AUTHTOK` for the wallet
//!   modules after it; then, when the daemon asks (the login screen only),
//!   `pam_info` and a hidden prompt for the code.
//! - `pam_sm_acct_mgmt`: whether the person may use this service.
//! - `pam_sm_setcred`: `PAM_SUCCESS`, nothing to set.
//!
//! The one argument, `socket=<path>`, moves the socket in debug builds only,
//! for tests; a release build ignores it.
//!
//! **No panic crosses into C**: each entry point runs inside
//! `catch_unwind`, and a panic is `PAM_SYSTEM_ERR`.

mod client;
mod flow;

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use zeroize::Zeroizing;

use flow::{PAM_AUTH_ERR, PAM_CONV_ERR, PAM_SUCCESS, PAM_SYSTEM_ERR, PAM_USER_UNKNOWN, Pam};

/// libpam's handle, opaque.
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

const PAM_SERVICE: c_int = 1;
const PAM_AUTHTOK: c_int = 6;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
const PAM_SILENT: c_int = 0x8000;
const LOG_NOTICE: c_int = 5;

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;
    fn pam_get_authtok(
        pamh: *mut PamHandle,
        item: c_int,
        authtok: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
    fn pam_prompt(
        pamh: *mut PamHandle,
        style: c_int,
        response: *mut *mut c_char,
        fmt: *const c_char,
        ...
    ) -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
}

/// `"%s"`, so no text of ours is ever read as a format.
const PERCENT_S: &CStr = c"%s";

/// The handle for one call into the module.
struct Handle(*mut PamHandle);

/// A copy of a C string as UTF-8, or `None`.
///
/// # Safety
/// `p` is null or points to a NUL-terminated string that stays valid for
/// the call.
unsafe fn text(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: as the caller promised.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// A C string with any NUL taken out, for text we pass on.
fn c(s: &str) -> CString {
    CString::new(s.replace('\0', "")).expect("no NUL is left")
}

impl Handle {
    /// One message, `style` `PAM_TEXT_INFO` or `PAM_ERROR_MSG`.
    fn say(&self, style: c_int, text: &str) {
        let msg = c(text);
        // SAFETY: `self.0` is the handle libpam gave this call; the format is
        // "%s" and its one argument a NUL-terminated string alive through the
        // call; a null response asks for none.
        unsafe {
            pam_prompt(
                self.0,
                style,
                std::ptr::null_mut(),
                PERCENT_S.as_ptr(),
                msg.as_ptr(),
            );
        }
    }
}

impl Pam for Handle {
    fn service(&self) -> Result<String, i32> {
        let mut item: *const c_void = std::ptr::null();
        // SAFETY: the handle is libpam's for this call; `item` is valid for
        // a write. PAM_SERVICE is a NUL-terminated string libpam owns.
        let rc = unsafe { pam_get_item(self.0, PAM_SERVICE, &mut item) };
        if rc != PAM_SUCCESS {
            return Err(rc);
        }
        // SAFETY: as above; it lives as long as the handle.
        unsafe { text(item.cast()) }.ok_or(PAM_SYSTEM_ERR)
    }

    fn user(&self) -> Result<String, i32> {
        let mut user: *const c_char = std::ptr::null();
        // SAFETY: the handle is libpam's; `user` is valid for a write; a null
        // prompt is libpam's own. The string is libpam's.
        let rc = unsafe { pam_get_user(self.0, &mut user, std::ptr::null()) };
        if rc != PAM_SUCCESS {
            return Err(rc);
        }
        // SAFETY: on success `user` is a NUL-terminated string libpam owns.
        unsafe { text(user) }.ok_or(PAM_USER_UNKNOWN)
    }

    fn password(&self) -> Result<Zeroizing<String>, i32> {
        let mut tok: *const c_char = std::ptr::null();
        // SAFETY: the handle is libpam's; `tok` is valid for a write; a null
        // prompt is libpam's own ("Password: "). The token is libpam's, kept
        // in PAM_AUTHTOK for the modules after this one, and not ours to
        // wipe or free.
        let rc = unsafe { pam_get_authtok(self.0, PAM_AUTHTOK, &mut tok, std::ptr::null()) };
        if rc != PAM_SUCCESS {
            return Err(rc);
        }
        if tok.is_null() {
            return Err(PAM_AUTH_ERR);
        }
        // SAFETY: on success `tok` is a NUL-terminated string libpam owns.
        let bytes = unsafe { CStr::from_ptr(tok) }.to_bytes();
        // A Mauvely password is a JavaScript string, so it is UTF-8.
        std::str::from_utf8(bytes)
            .map(|s| Zeroizing::new(s.to_owned()))
            .map_err(|_| PAM_AUTH_ERR)
    }

    fn secret(&self, prompt: &str) -> Result<Zeroizing<String>, i32> {
        let prompt = c(prompt);
        let mut answer: *mut c_char = std::ptr::null_mut();
        // SAFETY: the handle is libpam's; the format is "%s" and its argument
        // a NUL-terminated string alive through the call; `answer` is valid
        // for a write, and on success is a malloc'd string that is ours.
        let rc = unsafe {
            pam_prompt(
                self.0,
                PAM_PROMPT_ECHO_OFF,
                &mut answer,
                PERCENT_S.as_ptr(),
                prompt.as_ptr(),
            )
        };
        if rc != PAM_SUCCESS || answer.is_null() {
            if !answer.is_null() {
                // SAFETY: ours, from malloc, wiped before it is freed.
                unsafe { wipe_and_free(answer) };
            }
            return Err(if rc == PAM_SUCCESS { PAM_CONV_ERR } else { rc });
        }
        // SAFETY: a NUL-terminated string, ours until freed below.
        let copied = std::str::from_utf8(unsafe { CStr::from_ptr(answer) }.to_bytes())
            .map(|s| Zeroizing::new(s.to_owned()));
        // SAFETY: ours, from malloc, not used after this.
        unsafe { wipe_and_free(answer) };
        copied.map_err(|_| PAM_AUTH_ERR)
    }

    fn info(&self, text: &str) {
        self.say(PAM_TEXT_INFO, text);
    }

    fn error(&self, text: &str) {
        self.say(PAM_ERROR_MSG, text);
    }

    fn log(&self, text: &str) {
        let msg = c(&format!("pam_mauvely: {text}"));
        // SAFETY: the handle is libpam's; the format is "%s" and its argument
        // a NUL-terminated string alive through the call.
        unsafe { pam_syslog(self.0, LOG_NOTICE, PERCENT_S.as_ptr(), msg.as_ptr()) };
    }
}

/// Overwrites a malloc'd C string and frees it.
///
/// # Safety
/// `p` is a NUL-terminated string from malloc, used by nobody after this.
unsafe fn wipe_and_free(p: *mut c_char) {
    // SAFETY: as the caller promised: the string's bytes up to its NUL are
    // ours to write, and the pointer is free()'s to take.
    unsafe {
        let len = libc::strlen(p);
        for i in 0..len {
            std::ptr::write_volatile(p.add(i), 0);
        }
        libc::free(p.cast());
    }
}

/// The socket: `/run/mauvely/auth.sock`, or a debug build's `socket=`.
///
/// # Safety
/// `argv` holds `argc` NUL-terminated strings, as libpam passes them.
unsafe fn socket(argc: c_int, argv: *const *const c_char) -> PathBuf {
    let _ = (argc, argv);
    #[cfg(debug_assertions)]
    if !argv.is_null() {
        for i in 0..usize::try_from(argc).unwrap_or(0) {
            // SAFETY: as the caller promised: `argv[i]` for i < argc.
            let arg = unsafe { text(*argv.add(i)) };
            if let Some(path) = arg.as_deref().and_then(|a| a.strip_prefix("socket=")) {
                return PathBuf::from(path);
            }
        }
    }
    PathBuf::from(client::SOCKET)
}

/// Runs `f`, and turns a panic into `PAM_SYSTEM_ERR` rather than letting it
/// unwind into libpam.
fn guarded(f: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(PAM_SYSTEM_ERR)
}

/// # Safety
/// Called by libpam with its handle and the module's arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    guarded(|| {
        if pamh.is_null() {
            return PAM_SYSTEM_ERR;
        }
        // SAFETY: libpam's arguments, as it passes them.
        let socket = unsafe { socket(argc, argv) };
        flow::authenticate(&Handle(pamh), &socket, flags & PAM_SILENT != 0)
    })
}

/// # Safety
/// Called by libpam with its handle and the module's arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    guarded(|| {
        if pamh.is_null() {
            return PAM_SYSTEM_ERR;
        }
        // SAFETY: libpam's arguments, as it passes them.
        let socket = unsafe { socket(argc, argv) };
        flow::account(&Handle(pamh), &socket, flags & PAM_SILENT != 0)
    })
}

/// Nothing to set: the session is mauvely-session's.
///
/// # Safety
/// Called by libpam; nothing is read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
