//! The sign-in windows, drawn by `kdialog`, which is on the image.
//!
//! Two of them, one at a time:
//! - **the offer**, `--yesno` with its buttons named "Open the sign-in page"
//!   and "Later";
//! - **the code**, `--textbox -`, which stays up while the person types the
//!   code into the page and is taken down when the link ends.
//!
//! **The code never reaches an argv.** Every other user can read a process's
//! argv under `/proc`, and with the code one of them could approve this
//! computer's link for their own account (`docs/broker.md`). `--yesno` takes
//! its text as an argument, so the offer carries none of the code; the code
//! window is `--textbox -`, which reads its text from standard input, so the
//! code goes down a pipe only kdialog can read. The cost is that a text box has
//! one button, "OK", and that kdialog sets what it reads as rich text, which is
//! how the code comes out large: so only a string that is plainly a code is
//! ever sent.
//!
//! Each window is a child process waited on by a thread, so the broker is not
//! held up. How it ended is told once, as an [`Answer`], unless this module
//! took it down itself.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::Error;

/// How a window ended without being taken down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The first button: "Open the sign-in page".
    Accepted,
    /// "Later", or the window closed.
    Dismissed,
    /// kdialog crashed, or exited with a status it does not use for an
    /// answer: nothing was shown, so the caller falls back.
    Failed,
}

/// The program that draws the windows.
pub const PROGRAM: &str = "kdialog";

/// The windows' title.
const TITLE: &str = "Sign in to Mauvely";

/// How often a window is looked at to see whether it has ended.
const POLL: Duration = Duration::from_millis(100);

/// The most characters of a code that is shown. The server's is nine.
const CODE_MAX: usize = 32;

/// The arguments of the offer, which carry no code.
pub fn offer_argv() -> Vec<String> {
    [
        "--title",
        TITLE,
        "--icon",
        "user-identity",
        "--yes-label",
        "Open the sign-in page",
        "--no-label",
        "Later",
        "--yesno",
        "Link this computer to your Mauvely account.",
    ]
    .map(String::from)
    .to_vec()
}

/// The arguments of the code window: the text comes on standard input, and
/// the two numbers are the window's width and height.
pub fn code_argv() -> Vec<String> {
    [
        "--title",
        TITLE,
        "--icon",
        "user-identity",
        "--textbox",
        "-",
        "380",
        "150",
    ]
    .map(String::from)
    .to_vec()
}

/// What goes to the code window, or `None` when `code` is not plainly a code:
/// kdialog shows what it reads as rich text when it looks like some, so a
/// string with a tag in it is never passed on.
pub fn code_text(code: &str) -> Option<String> {
    let plain = !code.is_empty()
        && code.len() <= CODE_MAX
        && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    plain.then(|| format!("<p>Enter this code to sign in</p><h1 align=\"center\">{code}</h1>"))
}

pub struct Dialogs {
    program: PathBuf,
    /// The window that is up, if one is. A new one takes it down.
    open: Mutex<Option<Window>>,
}

/// A running kdialog. The thread that waits for it and whoever takes it down
/// share the child, so it is looked at, not blocked on: a kill and a wait
/// cannot then cross.
struct Window {
    child: Arc<Mutex<Child>>,
    /// Set before the kill, so the waiting thread says nothing of it.
    taken_down: Arc<AtomicBool>,
}

impl Window {
    fn kill(&self) {
        self.taken_down.store(true, Ordering::SeqCst);
        // Already gone is fine.
        let _ = lock(&self.child).kill();
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Dialogs {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Dialogs {
            program: program.into(),
            open: Mutex::new(None),
        }
    }

    /// Shows the offer, replacing a window already up. `then` is called from
    /// another thread when the person answers. An `Err` means it could not be
    /// shown.
    pub fn offer(&self, then: impl FnOnce(Answer) + Send + 'static) -> Result<(), Error> {
        self.show(&offer_argv(), None, then)
    }

    /// Shows the code, replacing a window already up. `failed` is called from
    /// another thread if the window crashed; the person closing it is not a
    /// failure. An `Err` means it could not be shown: `code` is not a code, or
    /// kdialog is not there.
    pub fn show_code(
        &self,
        code: &str,
        failed: impl FnOnce() + Send + 'static,
    ) -> Result<(), Error> {
        let text = code_text(code).ok_or("not a code a window can show")?;
        self.show(&code_argv(), Some(text), move |answer| {
            if answer == Answer::Failed {
                failed();
            }
        })
    }

    /// Takes down the window that is up. Its `then` is not called.
    pub fn close(&self) {
        if let Some(window) = lock(&self.open).take() {
            window.kill();
        }
    }

    fn show(
        &self,
        argv: &[String],
        stdin: Option<String>,
        then: impl FnOnce(Answer) + Send + 'static,
    ) -> Result<(), Error> {
        let mut open = lock(&self.open);
        if let Some(old) = open.take() {
            old.kill();
        }
        let program = self.program.display();
        let mut child = Command::new(&self.program)
            .args(argv)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::null())
            .spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
            // A few dozen bytes, well under a pipe's buffer, so it does not
            // wait for kdialog to read. Closed when dropped: the end of the
            // text.
            if let Err(e) = pipe.write_all(text.as_bytes()) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program}: {e}").into());
            }
        }
        let window = Window {
            child: Arc::new(Mutex::new(child)),
            taken_down: Arc::new(AtomicBool::new(false)),
        };
        let child = Arc::clone(&window.child);
        let taken_down = Arc::clone(&window.taken_down);
        *open = Some(window);
        drop(open);
        std::thread::Builder::new()
            .name("dialog".into())
            .spawn(move || {
                let status = loop {
                    match lock(&child).try_wait() {
                        Ok(Some(status)) => break status.code(),
                        Ok(None) => {}
                        Err(_) => break None,
                    }
                    std::thread::sleep(POLL);
                };
                if taken_down.load(Ordering::SeqCst) {
                    return;
                }
                then(match status {
                    Some(0) => Answer::Accepted,
                    // "Later", and the window's close: `--yesno` gives 1 for
                    // No and 2 when the dialog is rejected.
                    Some(1 | 2) => Answer::Dismissed,
                    _ => Answer::Failed,
                });
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::seal::tests::temp_dir;
    use std::fs;
    use std::path::Path;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(5);

    /// A `kdialog` that never draws anything: `fixtures/fake-kdialog.sh`,
    /// linked into a directory of its own, where it keeps what it was given.
    /// It is a link and not a file written here because a script that is open
    /// for writing in one test thread, while another forks, cannot be run
    /// ("text file busy").
    struct Fake {
        dir: PathBuf,
    }

    impl Fake {
        fn new() -> Self {
            let dir = temp_dir("dialog");
            fs::create_dir_all(&dir).unwrap();
            let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fake-kdialog.sh");
            std::os::unix::fs::symlink(script, dir.join("kdialog")).unwrap();
            Fake { dir }
        }

        fn dialogs(&self) -> Dialogs {
            Dialogs::new(self.dir.join("kdialog"))
        }

        fn set(&self, name: &str, text: &str) {
            fs::write(self.dir.join(name), text).unwrap();
        }

        fn unset(&self, name: &str) {
            let _ = fs::remove_file(self.dir.join(name));
        }

        /// How many times it has been run.
        fn runs(&self) -> usize {
            fs::read_to_string(self.dir.join("count"))
                .map(|c| c.trim().parse().unwrap())
                .unwrap_or(0)
        }

        fn argv(&self, n: usize) -> Vec<String> {
            fs::read_to_string(self.dir.join(format!("argv.{n}")))
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        /// The raw file, for looking for a string anywhere in it.
        fn argv_file(&self, n: usize) -> String {
            fs::read_to_string(self.dir.join(format!("argv.{n}"))).unwrap()
        }

        fn stdin(&self, n: usize) -> String {
            fs::read_to_string(self.dir.join(format!("stdin.{n}"))).unwrap()
        }

        fn pid(&self, n: usize) -> i32 {
            fs::read_to_string(self.dir.join(format!("pid.{n}")))
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        }

        /// Waits until it has been run `n` times and has written its
        /// arguments.
        fn wait_run(&self, n: usize) {
            let until = Instant::now() + WAIT;
            while !self.dir.join(format!("argv.{n}")).exists() {
                assert!(Instant::now() < until, "kdialog was not run {n} times");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            // Anything still held up is let go.
            self.set("exit", "0");
            self.unset("hold");
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn gone(pid: i32) -> bool {
        let until = Instant::now() + WAIT;
        // SAFETY: signal 0 only asks whether the process exists.
        while unsafe { libc::kill(pid, 0) } == 0 {
            // A child that has exited and not been reaped still answers.
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if stat.contains(") Z ") || stat.is_empty() {
                return true;
            }
            if Instant::now() > until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    /// The answer the window gives, or why it gave none.
    fn answer_of(
        run: impl FnOnce(mpsc::Sender<Answer>) -> Result<(), Error>,
    ) -> Result<Answer, RecvTimeoutError> {
        let (tx, rx) = mpsc::channel();
        run(tx).unwrap();
        rx.recv_timeout(WAIT)
    }

    #[test]
    fn the_offer_is_a_question_with_the_two_buttons_named_and_no_code() {
        assert_eq!(
            offer_argv(),
            [
                "--title",
                "Sign in to Mauvely",
                "--icon",
                "user-identity",
                "--yes-label",
                "Open the sign-in page",
                "--no-label",
                "Later",
                "--yesno",
                "Link this computer to your Mauvely account.",
            ]
        );

        let fake = Fake::new();
        let dialogs = fake.dialogs();
        answer_of(|tx| dialogs.offer(move |a| tx.send(a).unwrap())).unwrap();
        assert_eq!(fake.argv(1), offer_argv());
    }

    #[test]
    fn yes_is_accepted_and_no_and_a_closed_window_are_dismissed() {
        // 0 is the first button, 1 the second and 2 the window's own close:
        // the exit codes kdialog's --yesno gives (seen in a nested sway).
        for (exit, expected) in [
            ("0", Answer::Accepted),
            ("1", Answer::Dismissed),
            ("2", Answer::Dismissed),
        ] {
            let fake = Fake::new();
            fake.set("exit", exit);
            let dialogs = fake.dialogs();
            let got = answer_of(|tx| dialogs.offer(move |a| tx.send(a).unwrap()));
            assert_eq!(got, Ok(expected), "exit {exit}");
        }
    }

    #[test]
    fn a_window_that_crashed_or_exited_oddly_failed() {
        for exit in ["3", "255", "134"] {
            let fake = Fake::new();
            fake.set("exit", exit);
            let dialogs = fake.dialogs();
            let got = answer_of(|tx| dialogs.offer(move |a| tx.send(a).unwrap()));
            assert_eq!(got, Ok(Answer::Failed), "exit {exit}");
        }
        // Killed by a signal, as Qt does when it has no display.
        let fake = Fake::new();
        fake.set("crash", "");
        let dialogs = fake.dialogs();
        let got = answer_of(|tx| dialogs.offer(move |a| tx.send(a).unwrap()));
        assert_eq!(got, Ok(Answer::Failed));
    }

    #[test]
    fn a_program_that_is_not_there_is_an_error_at_once() {
        let dialogs = Dialogs::new("/nonexistent/kdialog");
        assert!(dialogs.offer(|_| panic!("no window")).is_err());
        assert!(
            dialogs
                .show_code("ABCD-EFGH", || panic!("no window"))
                .is_err()
        );
    }

    #[test]
    fn the_code_goes_to_kdialog_on_standard_input_and_never_in_its_argv() {
        let fake = Fake::new();
        let dialogs = fake.dialogs();
        let (tx, rx) = mpsc::channel();
        fake.set("hold", "");
        dialogs
            .show_code("ABCD-EFGH", move || tx.send(()).unwrap())
            .unwrap();
        fake.wait_run(1);

        // The arguments are fixed text.
        assert_eq!(fake.argv(1), code_argv());
        assert!(
            !fake.argv_file(1).contains("ABCD"),
            "the code is in kdialog's argv: {:?}",
            fake.argv(1)
        );
        // The text box reads standard input.
        assert!(fake.argv(1).windows(2).any(|w| w == ["--textbox", "-"]));
        // And gets the code, large, under the line that says what it is.
        let wait_for_stdin = Instant::now() + WAIT;
        while !fake.dir.join("stdin.1").exists() && Instant::now() < wait_for_stdin {
            std::thread::sleep(Duration::from_millis(10));
        }
        let text = fake.stdin(1);
        assert!(text.contains("Enter this code to sign in"), "{text}");
        assert!(
            text.contains(r#"<h1 align="center">ABCD-EFGH</h1>"#),
            "{text}"
        );

        // Closed by the person: not a failure, so nothing to fall back on.
        fake.unset("hold");
        assert_eq!(rx.recv_timeout(WAIT), Err(RecvTimeoutError::Disconnected));
    }

    #[test]
    fn a_code_window_that_crashed_is_told_so_the_code_can_be_shown_another_way() {
        let fake = Fake::new();
        fake.set("crash", "");
        let dialogs = fake.dialogs();
        let (tx, rx) = mpsc::channel();
        dialogs
            .show_code("ABCD-EFGH", move || tx.send(()).unwrap())
            .unwrap();
        assert_eq!(rx.recv_timeout(WAIT), Ok(()));
    }

    #[test]
    fn only_something_plainly_a_code_is_sent_to_a_window_that_reads_rich_text() {
        assert_eq!(
            code_text("ABCD-EFGH").unwrap(),
            "<p>Enter this code to sign in</p><h1 align=\"center\">ABCD-EFGH</h1>"
        );
        assert!(code_text("abcd-efgh2").is_some());
        for hostile in [
            "",
            "<img src=x>",
            "ABCD EFGH",
            "ABCD\nEFGH",
            "ABCD-EFGH;",
            "</h1><h1>x",
            "<b",
            "&amp;",
            "ÄBCD-EFGH",
            &"A".repeat(33),
        ] {
            assert_eq!(code_text(hostile), None, "{hostile:?}");
        }

        // So one that is not is refused before a window is started.
        let fake = Fake::new();
        let dialogs = fake.dialogs();
        assert!(
            dialogs
                .show_code("<img src=x>", || panic!("no window"))
                .is_err()
        );
        assert_eq!(fake.runs(), 0);
    }

    #[test]
    fn a_new_window_takes_the_old_one_down_and_close_takes_down_the_last() {
        let fake = Fake::new();
        fake.set("hold", "");
        let dialogs = fake.dialogs();

        let (tx1, rx1) = mpsc::channel();
        dialogs.offer(move |a| tx1.send(a).unwrap()).unwrap();
        fake.wait_run(1);
        let first = fake.pid(1);

        let (tx2, rx2) = mpsc::channel();
        dialogs
            .show_code("ABCD-EFGH", move || tx2.send(()).unwrap())
            .unwrap();
        fake.wait_run(2);
        let second = fake.pid(2);

        // The offer is gone, and was not "dismissed" or "failed": taking it
        // down was ours, and the person did nothing.
        assert!(gone(first), "the first window is still up");
        assert_eq!(rx1.recv_timeout(WAIT), Err(RecvTimeoutError::Disconnected));
        assert!(!gone_now(second), "the second window should be up");

        dialogs.close();
        assert!(gone(second), "the second window is still up");
        assert_eq!(rx2.recv_timeout(WAIT), Err(RecvTimeoutError::Disconnected));

        // Nothing up: closing is not an error.
        dialogs.close();
    }

    fn gone_now(pid: i32) -> bool {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        stat.is_empty() || stat.contains(") Z ")
    }

    #[test]
    fn a_window_that_failed_after_a_while_is_still_told() {
        // kdialog crashes minutes in, not at once.
        let fake = Fake::new();
        fake.set("hold", "");
        fake.set("exit", "3");
        let dialogs = fake.dialogs();
        let (tx, rx) = mpsc::channel();
        dialogs.offer(move |a| tx.send(a).unwrap()).unwrap();
        fake.wait_run(1);
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(300)),
            Err(RecvTimeoutError::Timeout)
        );
        fake.unset("hold");
        assert_eq!(rx.recv_timeout(WAIT), Ok(Answer::Failed));
    }
}
