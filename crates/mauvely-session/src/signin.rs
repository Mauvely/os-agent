//! The sign-in window, `mauvely-signin` (os-installer's `signin/`, built into
//! the image): a frameless Mauvely window around website-main's device-link
//! page, where the person signs in and approves the link. It is both the
//! offer and the code, so it stands in for both `dialog` windows.
//!
//! **The code never reaches an argv.** The window is started with no
//! arguments, and the code and the accounts origin go down its standard input
//! as one JSON line. Every other user can read a process's argv under
//! `/proc`, and with the code one of them could approve this computer's link
//! for their own account (`docs/broker.md`).
//!
//! The pipe stays open. When the link is approved, declined or expires, a
//! second line and the end of input tell the window to finish: it signs out
//! the session the person made in it, and exits. That comes after the claim:
//! website-main re-checks the approving session when the link is claimed, so
//! a session signed out first burns the link.
//!
//! The window says one thing back, `closed` on its standard output, when the
//! person closes it while it shows the sign-in: "Later", as closing the offer
//! was. It is hidden by then, and waits to be finished, so the broker can look
//! at the link once more in case they approved just before. Closed while it
//! shows the code for the browser, it only hides, and says nothing.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::Error;

/// Where the image installs it.
pub const PROGRAM: &str = "/usr/bin/mauvely-signin";

/// How a window ended without being told to finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// The person closed it: "Later". It waits, hidden, to be finished.
    Later,
    /// It crashed, or exited with a status other than 0: the code has to be
    /// shown another way.
    Failed,
}

/// How often a window is looked at to see whether it has ended.
const POLL: Duration = Duration::from_millis(100);

/// How long a window told to finish has to sign out and exit before it is
/// killed. The window gives the sign-out three seconds.
const FINISH_GRACE: Duration = Duration::from_secs(5);

/// The most characters of a code that is sent. The server's is nine.
const CODE_MAX: usize = 32;

/// The first line the window reads, or `None` when `code` is not plainly a
/// code: letters, digits and `-`. The window refuses anything else too.
pub fn start_line(code: &str, origin: &str) -> Option<String> {
    let plain = !code.is_empty()
        && code.len() <= CODE_MAX
        && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    plain.then(|| {
        format!(
            "{}\n",
            serde_json::json!({ "code": code, "origin": origin })
        )
    })
}

pub struct Signin {
    program: PathBuf,
    grace: Duration,
    /// The window that is up, if one is.
    open: Mutex<Option<Window>>,
}

/// A running window. Its waiting thread and `finish` share the child, which
/// is looked at, not blocked on, so a kill and a wait cannot cross.
struct Window {
    /// Held open: its end is the window's cue to finish.
    stdin: Option<ChildStdin>,
    /// Set when it is told to finish, so its ending is not reported.
    taken_down: Arc<AtomicBool>,
    /// When a window told to finish is killed if it has not exited.
    kill_at: Arc<Mutex<Option<Instant>>>,
}

/// Told once, by whichever comes first: the window's `closed`, or its end.
type Once = Arc<Mutex<Option<Box<dyn FnOnce(Ended) + Send>>>>;

fn tell(once: &Once, ended: Ended) {
    if let Some(f) = lock(once).take() {
        f(ended);
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Window {
    fn finish(mut self, grace: Duration) {
        self.taken_down.store(true, Ordering::SeqCst);
        *lock(&self.kill_at) = Some(Instant::now() + grace);
        if let Some(mut stdin) = self.stdin.take() {
            // Gone already is fine. Dropped here: the end of input.
            let _ = stdin.write_all(b"finish\n");
        }
    }
}

impl Signin {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Signin {
            program: program.into(),
            grace: FINISH_GRACE,
            open: Mutex::new(None),
        }
    }

    /// Whether the window is installed. Without it, the offer is a question
    /// and the code a `dialog` window, as before it.
    pub fn available(&self) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&self.program)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }

    /// Shows the window with `code`, for the accounts service at `origin`,
    /// finishing one already up. `ended` is called once, from another thread,
    /// if the person closes it or it fails, and never once it has been told
    /// to finish. An `Err` means it could not be started.
    pub fn show(
        &self,
        code: &str,
        origin: &str,
        ended: impl FnOnce(Ended) + Send + 'static,
    ) -> Result<(), Error> {
        let line = start_line(code, origin).ok_or("not a code the window takes")?;
        let mut open = lock(&self.open);
        if let Some(old) = open.take() {
            old.finish(self.grace);
        }
        let program = self.program.display();
        let mut child = Command::new(&self.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        let mut stdin = child.stdin.take().ok_or("no pipe to the window")?;
        // Under a hundred bytes, well under a pipe's buffer: this does not
        // wait for the window to read it.
        if let Err(e) = stdin.write_all(line.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{program}: {e}").into());
        }
        let window = Window {
            stdin: Some(stdin),
            taken_down: Arc::new(AtomicBool::new(false)),
            kill_at: Arc::new(Mutex::new(None)),
        };
        let (taken_down, kill_at) = (Arc::clone(&window.taken_down), Arc::clone(&window.kill_at));
        let once: Once = Arc::new(Mutex::new(Some(Box::new(ended))));
        if let Some(stdout) = child.stdout.take() {
            let (once, taken_down) = (Arc::clone(&once), Arc::clone(&taken_down));
            std::thread::Builder::new()
                .name("signin-out".into())
                .spawn(move || listen(stdout, &taken_down, &once))?;
        }
        *open = Some(window);
        drop(open);
        std::thread::Builder::new()
            .name("signin".into())
            .spawn(move || watch(child, &taken_down, &kill_at, &once))?;
        Ok(())
    }

    /// Tells the window that is up to finish: it signs out and exits, or is
    /// killed after a few seconds. Its ending is not reported. Nothing up is
    /// fine.
    pub fn finish(&self) {
        if let Some(window) = lock(&self.open).take() {
            window.finish(self.grace);
        }
    }
}

/// Reads what the window says until it ends. `closed` is the person closing
/// it; anything else is not this protocol and is ignored.
fn listen(stdout: ChildStdout, taken_down: &AtomicBool, once: &Once) {
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { return };
        if line == "closed" && !taken_down.load(Ordering::SeqCst) {
            tell(once, Ended::Later);
        }
    }
}

/// Waits for the window to end, and says how unless it was told to finish or
/// has already said it was closed.
fn watch(mut child: Child, taken_down: &AtomicBool, kill_at: &Mutex<Option<Instant>>, once: &Once) {
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {}
            Err(_) => break None,
        }
        if lock(kill_at).is_some_and(|at| Instant::now() >= at) {
            eprintln!("mauvely-session: the sign-in window did not finish; stopped");
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        std::thread::sleep(POLL);
    };
    if taken_down.load(Ordering::SeqCst) {
        return;
    }
    tell(
        once,
        match status {
            Some(0) => Ended::Later,
            _ => Ended::Failed,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::seal::tests::temp_dir;
    use std::fs;
    use std::path::Path;
    use std::sync::mpsc::{self, RecvTimeoutError};

    const WAIT: Duration = Duration::from_secs(5);
    const ORIGIN: &str = "https://mauvely.com";

    /// A `mauvely-signin` that draws nothing: `fixtures/fake-signin.sh`,
    /// linked into a directory of its own, where it keeps what it was given.
    /// A link, not a file written here, for the reason `dialog`'s is.
    struct Fake {
        dir: PathBuf,
    }

    impl Fake {
        fn new() -> Self {
            let dir = temp_dir("signin");
            fs::create_dir_all(&dir).unwrap();
            let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fake-signin.sh");
            std::os::unix::fs::symlink(script, dir.join("mauvely-signin")).unwrap();
            Fake { dir }
        }

        fn signin(&self) -> Signin {
            let mut s = Signin::new(self.dir.join("mauvely-signin"));
            s.grace = Duration::from_millis(500);
            s
        }

        fn set(&self, name: &str, text: &str) {
            fs::write(self.dir.join(name), text).unwrap();
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.dir.join(name)).unwrap()
        }

        fn runs(&self) -> usize {
            fs::read_to_string(self.dir.join("count"))
                .map(|c| c.trim().parse().unwrap())
                .unwrap_or(0)
        }

        fn pid(&self, n: usize) -> i32 {
            self.read(&format!("pid.{n}")).trim().parse().unwrap()
        }

        /// Waits for `name` to be written.
        fn wait_for(&self, name: &str) {
            let until = Instant::now() + WAIT;
            while !self.dir.join(name).exists() {
                assert!(Instant::now() < until, "{name} was not written");
                std::thread::sleep(Duration::from_millis(10));
            }
            // Written whole: the fake writes each file with one printf.
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.set("quit", "");
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// Whether the process has ended (or ended and is not yet reaped).
    fn gone(pid: i32) -> bool {
        let until = Instant::now() + WAIT;
        loop {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if stat.is_empty() || stat.contains(") Z ") {
                return true;
            }
            if Instant::now() > until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn show(signin: &Signin, code: &str) -> mpsc::Receiver<Ended> {
        let (tx, rx) = mpsc::channel();
        signin
            .show(code, ORIGIN, move |e| tx.send(e).unwrap())
            .unwrap();
        rx
    }

    #[test]
    fn the_first_line_is_the_code_and_the_origin() {
        assert_eq!(
            start_line("ABCD-EFGH", ORIGIN).unwrap(),
            "{\"code\":\"ABCD-EFGH\",\"origin\":\"https://mauvely.com\"}\n"
        );
        assert!(start_line("abcd2", "http://127.0.0.1:8787").is_some());
        for hostile in [
            "",
            "ABCD EFGH",
            "ABCD\nEFGH",
            "<b>",
            "ABCD\"}",
            "ÄBCD",
            &"A".repeat(33),
        ] {
            assert_eq!(start_line(hostile, ORIGIN), None, "{hostile:?}");
        }
    }

    #[test]
    fn the_code_goes_on_standard_input_and_never_in_an_argv() {
        let fake = Fake::new();
        let signin = fake.signin();
        let _ended = show(&signin, "ABCD-EFGH");
        fake.wait_for("stdin.1");
        // Started with no arguments at all.
        assert_eq!(fake.read("argv.1"), "");
        assert_eq!(
            fake.read("stdin.1"),
            "{\"code\":\"ABCD-EFGH\",\"origin\":\"https://mauvely.com\"}\n"
        );
        // Nor in its environment, which /proc also shows other users' tools.
        let environ = fs::read(format!("/proc/{}/environ", fake.pid(1))).unwrap();
        assert!(!environ.windows(9).any(|w| w == b"ABCD-EFGH"));
        signin.finish();
    }

    #[test]
    fn finish_is_a_line_then_the_end_of_input_and_is_not_reported() {
        let fake = Fake::new();
        let signin = fake.signin();
        let ended = show(&signin, "ABCD-EFGH");
        fake.wait_for("stdin.1");
        signin.finish();
        fake.wait_for("finish.1");
        assert_eq!(fake.read("finish.1"), "finish\n");
        assert!(gone(fake.pid(1)));
        assert_eq!(
            ended.recv_timeout(WAIT),
            Err(RecvTimeoutError::Disconnected)
        );
        // Nothing up: finishing again is not an error.
        signin.finish();
    }

    #[test]
    fn the_end_of_input_alone_finishes_it_when_the_session_goes() {
        let fake = Fake::new();
        {
            let signin = fake.signin();
            let _ended = show(&signin, "ABCD-EFGH");
            fake.wait_for("stdin.1");
            // mauvely-session exits without a word: its end of the pipe goes.
        }
        fake.wait_for("finish.1");
        assert_eq!(fake.read("finish.1"), "EOF\n");
        assert!(gone(fake.pid(1)));
    }

    #[test]
    fn closed_by_the_person_is_later_and_it_waits_to_be_finished() {
        let fake = Fake::new();
        let signin = fake.signin();
        let ended = show(&signin, "ABCD-EFGH");
        fake.wait_for("stdin.1");
        fake.set("close", "");
        assert_eq!(ended.recv_timeout(WAIT), Ok(Ended::Later));
        // Hidden, not gone: it signs out only when told, after the broker's
        // last look at the link.
        std::thread::sleep(Duration::from_millis(200));
        assert!(!gone_now(fake.pid(1)), "the window did not wait");
        signin.finish();
        fake.wait_for("finish.1");
        assert_eq!(fake.read("finish.1"), "finish\n");
        assert!(gone(fake.pid(1)));
        // Told once.
        assert_eq!(
            ended.recv_timeout(WAIT),
            Err(RecvTimeoutError::Disconnected)
        );
    }

    #[test]
    fn a_window_that_exits_by_itself_is_later_at_0_and_failed_otherwise() {
        let fake = Fake::new();
        fake.set("quit", "");
        let signin = fake.signin();
        let ended = show(&signin, "ABCD-EFGH");
        assert_eq!(ended.recv_timeout(WAIT), Ok(Ended::Later));
        for exit in ["1", "2", "3", "134"] {
            let fake = Fake::new();
            fake.set("exit", exit);
            fake.set("quit", "");
            let signin = fake.signin();
            let ended = show(&signin, "ABCD-EFGH");
            assert_eq!(ended.recv_timeout(WAIT), Ok(Ended::Failed), "exit {exit}");
        }
        // Killed by a signal, as Qt aborts without a display; minutes in, not
        // at once.
        let fake = Fake::new();
        let signin = fake.signin();
        let ended = show(&signin, "ABCD-EFGH");
        fake.wait_for("stdin.1");
        assert_eq!(
            ended.recv_timeout(Duration::from_millis(300)),
            Err(RecvTimeoutError::Timeout)
        );
        fake.set("crash", "");
        assert_eq!(ended.recv_timeout(WAIT), Ok(Ended::Failed));
    }

    #[test]
    fn a_window_that_does_not_finish_is_stopped() {
        let fake = Fake::new();
        fake.set("stubborn", "");
        let signin = fake.signin();
        let ended = show(&signin, "ABCD-EFGH");
        fake.wait_for("stdin.1");
        signin.finish();
        fake.wait_for("finish.1");
        // Still there after being told: killed once the grace has passed.
        assert!(gone(fake.pid(1)), "the window is still up");
        assert_eq!(
            ended.recv_timeout(WAIT),
            Err(RecvTimeoutError::Disconnected)
        );
    }

    #[test]
    fn a_new_window_finishes_the_old_one() {
        let fake = Fake::new();
        let signin = fake.signin();
        let first = show(&signin, "ABCD-EFGH");
        fake.wait_for("stdin.1");
        let _second = show(&signin, "WXYZ-1234");
        fake.wait_for("stdin.2");
        fake.wait_for("finish.1");
        assert!(gone(fake.pid(1)));
        assert_eq!(
            first.recv_timeout(WAIT),
            Err(RecvTimeoutError::Disconnected)
        );
        assert!(!gone_now(fake.pid(2)), "the second window should be up");
        signin.finish();
    }

    fn gone_now(pid: i32) -> bool {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        stat.is_empty() || stat.contains(") Z ")
    }

    #[test]
    fn not_installed_is_not_available_and_cannot_show() {
        let signin = Signin::new("/nonexistent/mauvely-signin");
        assert!(!signin.available());
        assert!(
            signin
                .show("ABCD-EFGH", ORIGIN, |_| panic!("no window"))
                .is_err()
        );

        // A file that cannot be run is not the window either.
        let fake = Fake::new();
        let plain = fake.dir.join("not-a-program");
        fs::write(&plain, "").unwrap();
        assert!(!Signin::new(&plain).available());
        assert!(fake.signin().available());
    }

    #[test]
    fn something_that_is_not_a_code_is_refused_before_a_window_starts() {
        let fake = Fake::new();
        let signin = fake.signin();
        assert!(
            signin
                .show("<img src=x>", ORIGIN, |_| panic!("no window"))
                .is_err()
        );
        assert_eq!(fake.runs(), 0);
    }
}
