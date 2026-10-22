use super::*;
use std::cell::RefCell;
use std::io::Cursor;
use std::os::unix::net::UnixListener;

const TOKEN: &str = "tok_0123456789abcdefABCDEF-_0123456789abcdef";

fn framed(messages: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in messages {
        frame::write(&mut out, m).unwrap();
    }
    out
}

fn unframe(mut bytes: &[u8]) -> Vec<Value> {
    let mut out = Vec::new();
    while let Some(m) = frame::read(&mut bytes, 1 << 20).unwrap() {
        out.push(serde_json::from_slice(&m).unwrap());
    }
    out
}

fn granted(origin: &str) -> Vec<u8> {
    format!(
        "{{\"v\":1,\"ok\":true,\"token\":\"{TOKEN}\",\"expiresAt\":1771200000,\
         \"email\":\"ada@example.com\",\"origin\":\"{origin}\"}}\n"
    )
    .into_bytes()
}

#[test]
fn frames_carry_a_native_length() {
    let bytes = framed(&[b"{\"op\":\"origin\"}"]);
    assert_eq!(&bytes[..4], &15u32.to_ne_bytes());
    assert_eq!(&bytes[4..], b"{\"op\":\"origin\"}");
    let mut input = Cursor::new(framed(&[b"one", b"", b"three"]));
    assert_eq!(frame::read(&mut input, 64).unwrap().unwrap(), b"one");
    assert_eq!(frame::read(&mut input, 64).unwrap().unwrap(), b"");
    assert_eq!(frame::read(&mut input, 64).unwrap().unwrap(), b"three");
    // Closed between messages: the end, not an error.
    assert!(frame::read(&mut input, 64).unwrap().is_none());
}

#[test]
fn a_frame_cut_short_is_an_error() {
    // Inside the length.
    let mut input = Cursor::new(vec![5u8, 0]);
    assert!(matches!(
        frame::read(&mut input, 64),
        Err(frame::ReadError::Io(_))
    ));
    // Inside the body.
    let mut bytes = 10u32.to_ne_bytes().to_vec();
    bytes.extend_from_slice(b"short");
    assert!(matches!(
        frame::read(&mut Cursor::new(bytes), 64),
        Err(frame::ReadError::Io(_))
    ));
}

#[test]
fn a_frame_over_the_limit_is_not_read() {
    let mut bytes = (MAX_REQUEST as u32 + 1).to_ne_bytes().to_vec();
    bytes.extend(std::iter::repeat_n(b'x', MAX_REQUEST + 1));
    let mut input = Cursor::new(bytes);
    assert!(matches!(
        frame::read(&mut input, MAX_REQUEST),
        Err(frame::ReadError::TooLarge(n)) if n == MAX_REQUEST + 1
    ));
    // Only the length was consumed.
    assert_eq!(input.position(), 4);
    // A length the size of the whole address space is refused before any
    // allocation.
    let mut input = Cursor::new(u32::MAX.to_ne_bytes().to_vec());
    assert!(matches!(
        frame::read(&mut input, MAX_REQUEST),
        Err(frame::ReadError::TooLarge(_))
    ));
}

#[test]
fn only_two_ops() {
    assert_eq!(parse(br#"{"op":"origin"}"#), Some(Op::Origin));
    assert_eq!(parse(br#"{"op":"browser"}"#), Some(Op::Browser));
    // Other fields are ignored: nothing of the message reaches the broker.
    assert_eq!(
        parse(br#"{"op":"browser","client":"compose"}"#),
        Some(Op::Browser)
    );
    for message in [
        &b""[..],
        b"null",
        b"\"browser\"",
        b"[\"browser\"]",
        br#"{"op":"token","client":"compose"}"#,
        br#"{"op":"Browser"}"#,
        br#"{"op":1}"#,
        br#"{"v":1}"#,
        b"{\"op\":\"browser\"",
    ] {
        assert_eq!(parse(message), None, "{message:?}");
    }
}

#[test]
fn the_broker_lines_are_the_hosts_own() {
    assert_eq!(Op::Origin.line(), b"{\"v\":1,\"op\":\"origin\"}\n");
    assert_eq!(Op::Browser.line(), b"{\"v\":1,\"op\":\"browser\"}\n");
}

#[test]
fn a_session_is_passed_on_without_the_address() {
    assert_eq!(
        reduce(Op::Browser, &granted("https://mauvely.com")),
        json!({"ok":true,"token":TOKEN,"expiresAt":1771200000u64,"origin":"https://mauvely.com"})
    );
    assert_eq!(
        reduce(Op::Browser, &granted("https://mauvely.dev"))["origin"],
        "https://mauvely.dev"
    );
    // The origin op takes only the origin, even from a fuller answer.
    assert_eq!(
        reduce(Op::Origin, &granted("https://mauvely.com")),
        json!({"ok":true,"origin":"https://mauvely.com"})
    );
    assert_eq!(
        reduce(
            Op::Origin,
            b"{\"v\":1,\"ok\":true,\"origin\":\"https://mauvely.dev\"}\n"
        ),
        json!({"ok":true,"origin":"https://mauvely.dev"})
    );
}

#[test]
fn a_refusal_keeps_only_its_reason() {
    assert_eq!(
        reduce(
            Op::Browser,
            br#"{"v":1,"ok":false,"reason":"sso_required","org":"northgate","start":"https://mauvely.com/api/auth/sso/start?org=northgate"}"#
        ),
        json!({"ok":false,"reason":"sso_required"})
    );
    assert_eq!(
        reduce(Op::Origin, br#"{"v":1,"ok":false,"reason":"forbidden"}"#),
        json!({"ok":false,"reason":"forbidden"})
    );
}

#[test]
fn anything_else_is_a_bad_response() {
    let bad = json!({"ok":false,"reason":"bad_response"});
    let with = |field: &str, value: &str| {
        let mut v: Value = serde_json::from_slice(&granted("https://mauvely.com")).unwrap();
        v[field] = serde_json::from_str(value).unwrap();
        v.to_string().into_bytes()
    };
    for line in [
        b"".to_vec(),
        b"not json\n".to_vec(),
        b"[]\n".to_vec(),
        // Not this protocol's version, or none.
        with("v", "2"),
        with("v", "\"1\""),
        br#"{"ok":false,"reason":"signed_out"}"#.to_vec(),
        // Origins a cookie must never be set for.
        granted("http://localhost:8787"),
        granted("https://mauvely.com.evil.example"),
        granted("https://evil.example"),
        granted("http://mauvely.com"),
        with("origin", "null"),
        // Tokens a cookie could not carry, or that are not website-main's.
        with("token", "\"short\""),
        with("token", "\"has;semicolon_0123456789abcdef\""),
        with("token", "\"has space_0123456789abcdefgh\""),
        with("token", &format!("\"{}\"", "a".repeat(257))),
        with("token", "null"),
        // An expiry JavaScript cannot hold, or none.
        with("expiresAt", "0"),
        with("expiresAt", "-5"),
        with("expiresAt", "1.5"),
        with("expiresAt", "9007199254740992"),
        with("expiresAt", "\"1771200000\""),
        // A reason that is not a code.
        br#"{"v":1,"ok":false,"reason":"Signed out"}"#.to_vec(),
        br#"{"v":1,"ok":false,"reason":""}"#.to_vec(),
        br#"{"v":1,"ok":false}"#.to_vec(),
        br#"{"v":1,"ok":"false","reason":"signed_out"}"#.to_vec(),
        format!(r#"{{"v":1,"ok":false,"reason":"{}"}}"#, "a".repeat(33)).into_bytes(),
    ] {
        assert_eq!(
            reduce(Op::Browser, &line),
            bad,
            "{}",
            String::from_utf8_lossy(&line)
        );
    }
    // An origin answer without an origin.
    assert_eq!(reduce(Op::Origin, br#"{"v":1,"ok":true}"#), bad);
    // A line past the broker's own limit, whatever it holds.
    let mut long = granted("https://mauvely.com");
    long.splice(1..1, std::iter::repeat_n(b' ', MAX_LINE));
    assert_eq!(reduce(Op::Browser, &long), bad);
}

/// Records what it was asked and answers from a list.
struct Fake {
    asked: RefCell<Vec<Vec<u8>>>,
    answers: RefCell<Vec<io::Result<Vec<u8>>>>,
}

impl Fake {
    fn new(answers: Vec<io::Result<Vec<u8>>>) -> Fake {
        Fake {
            asked: RefCell::default(),
            answers: RefCell::new(answers),
        }
    }
}

impl Broker for Fake {
    fn ask(&self, line: &[u8]) -> io::Result<Vec<u8>> {
        self.asked.borrow_mut().push(line.to_vec());
        self.answers.borrow_mut().remove(0)
    }
}

#[test]
fn serves_until_the_browser_closes() {
    let fake = Fake::new(vec![
        Ok(b"{\"v\":1,\"ok\":true,\"origin\":\"https://mauvely.com\"}\n".to_vec()),
        Ok(granted("https://mauvely.com")),
        Err(io::ErrorKind::ConnectionRefused.into()),
    ]);
    let mut input = Cursor::new(framed(&[
        br#"{"op":"origin"}"#,
        br#"{"op":"browser","label":"injected"}"#,
        br#"{"op":"token","client":"compose"}"#,
        br#"{"op":"browser"}"#,
    ]));
    let mut output = Vec::new();
    serve(&mut input, &mut output, Some(&fake)).unwrap();
    assert_eq!(
        unframe(&output),
        [
            json!({"ok":true,"origin":"https://mauvely.com"}),
            json!({"ok":true,"token":TOKEN,"expiresAt":1771200000u64,"origin":"https://mauvely.com"}),
            json!({"ok":false,"reason":"unknown_op"}),
            json!({"ok":false,"reason":"unavailable"}),
        ]
    );
    // The token op never reached the broker, and nothing of the messages did.
    assert_eq!(
        *fake.asked.borrow(),
        [Op::Origin.line(), Op::Browser.line(), Op::Browser.line()]
    );
}

#[test]
fn without_a_runtime_directory_nothing_is_asked() {
    let mut input = Cursor::new(framed(&[br#"{"op":"browser"}"#]));
    let mut output = Vec::new();
    serve(&mut input, &mut output, None).unwrap();
    assert_eq!(
        unframe(&output),
        [json!({"ok":false,"reason":"unavailable"})]
    );
}

#[test]
fn a_message_over_the_limit_ends_it() {
    let fake = Fake::new(vec![]);
    let big = vec![b' '; MAX_REQUEST + 1];
    let mut input = Cursor::new(framed(&[&big, br#"{"op":"browser"}"#]));
    let mut output = Vec::new();
    assert!(serve(&mut input, &mut output, Some(&fake)).is_err());
    assert_eq!(unframe(&output), [json!({"ok":false,"reason":"too_large"})]);
    assert!(fake.asked.borrow().is_empty());
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mauvely-host-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn asks_the_socket_one_line() {
    let dir = scratch("socket");
    let path = dir.join("broker");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = Vec::new();
        BufReader::new(&mut stream)
            .read_until(b'\n', &mut line)
            .unwrap();
        stream.write_all(&granted("https://mauvely.dev")).unwrap();
        line
    });
    let socket = Socket {
        path: path.clone(),
        timeout: Duration::from_secs(5),
    };
    let answer = socket.ask(Op::Browser.line()).unwrap();
    assert_eq!(server.join().unwrap(), Op::Browser.line());
    assert_eq!(answer, granted("https://mauvely.dev"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_broker_that_is_not_there_or_silent_is_an_error() {
    let dir = scratch("silent");
    let missing = Socket {
        path: dir.join("nothing"),
        timeout: Duration::from_secs(1),
    };
    assert!(missing.ask(Op::Origin.line()).is_err());

    let path = dir.join("broker");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        drop(stream);
    });
    let silent = Socket {
        path,
        timeout: Duration::from_millis(300),
    };
    let started = std::time::Instant::now();
    assert!(silent.ask(Op::Origin.line()).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    server.join().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_long_line_is_cut_and_refused() {
    let mut endless = std::io::repeat(b'x');
    let line = read_line(&mut endless).unwrap();
    assert_eq!(line.len(), MAX_LINE + 2);
    assert_eq!(
        reduce(Op::Browser, &line),
        json!({"ok":false,"reason":"bad_response"})
    );
}

#[test]
fn the_runtime_directory_must_be_absolute() {
    let at = |v: Option<&str>| Socket::in_runtime(v.map(Into::into)).map(|s| s.path);
    assert_eq!(
        at(Some("/run/user/1000")),
        Some(PathBuf::from("/run/user/1000/mauvely/broker"))
    );
    // Relative would be the browser's working directory.
    assert_eq!(at(Some("run/user/1000")), None);
    assert_eq!(at(Some("")), None);
    assert_eq!(at(None), None);
}
