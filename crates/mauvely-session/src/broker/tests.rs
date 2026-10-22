//! The broker against a fake accounts server.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::seal::OsSession;
use super::testing::*;
use super::{Clock, LoginSession, stale_after};

const COMPOSE: &str = r#"{"v":1,"op":"token","client":"compose"}"#;
const BROWSER: &str = r#"{"v":1,"op":"browser"}"#;
const ORIGIN: &str = r#"{"v":1,"op":"origin"}"#;
const ALIVE: &str = r#"{"user":{"id":"usr_1","email":"ada@example.com"}}"#;
const DEAD: &str = r#"{"user":null,"totpSatisfied":false}"#;

fn error(code: &str) -> String {
    format!(r#"{{"error":{{"code":"{code}","message":"No."}},"requestId":"r1"}}"#)
}

fn start(interval: u64, expires_in: u64) -> (u16, String) {
    (
        200,
        format!(
            r#"{{"deviceCode":"dc_secret","userCode":"ABCD-EFGH","verificationUri":"{{BASE}}/link",
                "verificationUriComplete":"{{BASE}}/link?code=ABCD-EFGH",
                "interval":{interval},"expiresIn":{expires_in}}}"#
        ),
    )
}

fn pending() -> (u16, String) {
    (202, r#"{"status":"pending","interval":5}"#.into())
}

fn granted(a: &serde_json::Value, token: &str) {
    assert_eq!(a["v"], 1, "{a}");
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["token"], token, "{a}");
    assert_eq!(a["email"], "ada@example.com");
}

fn refused(a: &serde_json::Value, reason: &str) {
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["reason"], reason, "{a}");
    assert!(a.get("token").is_none());
}

#[test]
fn stale_a_tenth_or_five_minutes_early() {
    // A 90-day session: five minutes before it expires.
    assert_eq!(stale_after(0, 90 * 86_400), 90 * 86_400 - 300);
    // A one-hour session: five minutes. Ten minutes: one minute.
    assert_eq!(stale_after(1000, 1000 + 3600), 1000 + 3300);
    assert_eq!(stale_after(1000, 1000 + 600), 1000 + 540);
    // Expired on arrival, or the clock is odd: stale at once.
    assert_eq!(stale_after(1000, 900), 900);
    assert_eq!(stale_after(1000, 1000), 1000);
}

#[test]
fn signed_out_offers_a_link_once_and_answers_signed_out() {
    let mut f = Fixture::new(vec![]);
    assert_eq!(f.offers(), 0, "the session loop offers, not load");
    f.broker.offer_if_wanted();
    f.broker.offer_if_wanted();
    assert_eq!(f.offers(), 1);

    refused(&f.ask(&compose(), COMPOSE), "signed_out");
    refused(&f.ask(&firefox(), BROWSER), "signed_out");
    assert!(f.requests().is_empty());
}

#[test]
fn linking_opens_the_page_then_seals_the_session() {
    let mut f = Fixture::new(vec![
        start(5, 600),
        pending(),
        (429, error("rate_limited")),
        (200, Fixture::minted("tok_os_new", 90 * 86_400)),
    ]);
    f.broker.link();

    // The page opens without the code, which is shown to the person alone.
    assert_eq!(
        *f.desktop.opened.lock().unwrap(),
        [format!("{}/link", f.base)]
    );
    assert_eq!(*f.desktop.codes.lock().unwrap(), ["ABCD-EFGH"]);
    // And the account it was linked to is said.
    assert_eq!(*f.desktop.signed_in.lock().unwrap(), ["ada@example.com"]);
    let stored = f.stored().unwrap();
    assert_eq!(stored.token, "tok_os_new");
    assert_eq!(stored.expires_at, NOW + 90 * 86_400);
    assert_eq!(stored.origin, f.base);
    // The plain token is not in the file.
    let raw = std::fs::read(&f.store).unwrap();
    assert!(!raw.windows(10).any(|w| w == b"tok_os_new"));

    let reqs = f.requests();
    let lines: Vec<String> = reqs.iter().map(|r| r.line()).collect();
    assert_eq!(
        lines,
        [
            "POST /api/auth/device/start",
            "POST /api/auth/device/token",
            "POST /api/auth/device/token",
            "POST /api/auth/device/token",
        ]
    );
    let body = reqs[0].json();
    assert_eq!(body["client"], "os");
    assert_eq!(body["deviceName"], "Mauvely OS on testhost");
    assert_eq!(reqs[1].json()["deviceCode"], "dc_secret");
    assert!(reqs.iter().all(|r| r.header("Authorization").is_none()));

    // Polled every 5 s, then every 15 s after the 429.
    assert_eq!(f.clock.now(), NOW + 5 + 5 + 15);
    // Signed in: nothing more to offer.
    f.broker.offer_if_wanted();
    assert_eq!(f.offers(), 0);
}

#[test]
fn a_declined_or_expired_link_leaves_it_signed_out() {
    let mut f = Fixture::new(vec![
        start(5, 600),
        pending(),
        (400, error("access_denied")),
    ]);
    f.broker.offer_if_wanted();
    f.broker.link();
    assert!(f.stored().is_none());
    refused(&f.ask(&compose(), COMPOSE), "signed_out");
    // Declined: the code is taken away, and not offered again until the
    // next login.
    assert_eq!(f.desktop.withdrawn.load(Ordering::SeqCst), 1);
    assert!(f.desktop.signed_in.lock().unwrap().is_empty());
    f.broker.offer_if_wanted();
    assert_eq!(f.offers(), 1);
    assert_eq!(f.requests().len(), 3);

    // Expired: polled every 30 s for 60 s, then given up on.
    let mut f = Fixture::new(vec![start(30, 60), pending(), pending()]);
    f.broker.link();
    assert!(f.stored().is_none());
    assert_eq!(f.desktop.withdrawn.load(Ordering::SeqCst), 1);
    assert_eq!(f.requests().len(), 3);
}

#[test]
fn a_link_that_cannot_start_is_offered_again_as_a_question() {
    let mut f = Fixture::new(vec![(503, String::new())]);
    f.broker.offer_if_wanted();
    f.broker.link();
    assert_eq!(f.offers(), 2);
    // The first offer may be the sign-in window, which links by itself; the
    // second asks, so a server that cannot be reached is not asked again and
    // again.
    assert_eq!(*f.desktop.asks.lock().unwrap(), [false, true]);
    assert!(f.desktop.opened.lock().unwrap().is_empty());
    assert_eq!(f.requests().len(), 1);

    // A link page on another origin is never opened.
    let evil = (
        200,
        r#"{"deviceCode":"d","userCode":"A","verificationUri":"https://evil.example/link"}"#.into(),
    );
    let mut f = Fixture::new(vec![evil]);
    f.broker.link();
    assert!(f.desktop.opened.lock().unwrap().is_empty());
    assert_eq!(f.requests().len(), 1);

    // No browser to open it in: offered again, and nothing polled.
    let mut f = Fixture::new(vec![start(5, 600)]);
    f.desktop.open_fails.store(true, Ordering::SeqCst);
    f.broker.link();
    assert_eq!(f.offers(), 1);
    assert_eq!(f.requests().len(), 1);
}

#[test]
fn an_app_session_is_minted_once_then_answered_while_it_lives() {
    let mut f = Fixture::signed_in(vec![
        (200, Fixture::minted("tok_compose", 90 * 86_400)),
        (200, ALIVE.into()),
    ]);
    let line = r#"{"v":1,"op":"token","client":"compose","label":"Compose on testhost"}"#;
    let a = f.ask(&compose(), line);
    granted(&a, "tok_compose");
    assert_eq!(a["expiresAt"], NOW + 90 * 86_400);
    assert_eq!(a["origin"], f.base.as_str());
    granted(&f.ask(&compose(), COMPOSE), "tok_compose");

    let reqs = f.requests();
    assert_eq!(reqs[0].line(), "POST /api/auth/apps/token");
    assert_eq!(reqs[0].header("Authorization"), Some("Bearer tok_os"));
    assert_eq!(
        reqs[0].json(),
        serde_json::json!({"client":"compose","deviceLabel":"Compose on testhost"})
    );
    // The second answer is checked with the server, not minted.
    assert_eq!(reqs[1].line(), "GET /api/auth/me");
    assert_eq!(reqs[1].header("Authorization"), Some("Bearer tok_compose"));
    assert_eq!(reqs.len(), 2);
}

#[test]
fn a_revoked_session_is_minted_again() {
    // Signed out in the page, or revoked in the Devices tab: the caller asks
    // again and gets a new one.
    let mut f = Fixture::signed_in(vec![
        (200, Fixture::minted("tok_1", 30 * 86_400)),
        (200, DEAD.into()),
        (200, Fixture::minted("tok_2", 30 * 86_400)),
    ]);
    granted(&f.ask(&firefox(), BROWSER), "tok_1");
    granted(&f.ask(&firefox(), BROWSER), "tok_2");
    let lines: Vec<String> = f.requests().iter().map(|r| r.line()).collect();
    assert_eq!(
        lines,
        [
            "POST /api/auth/browser/token",
            "GET /api/auth/me",
            "POST /api/auth/browser/token"
        ]
    );
}

#[test]
fn a_session_near_its_end_is_minted_again_without_asking() {
    // An organisation's one-hour limit: stale five minutes early.
    let mut f = Fixture::signed_in(vec![
        (200, Fixture::minted("tok_1", 3600)),
        (200, ALIVE.into()),
        (200, Fixture::minted("tok_2", 7200)),
    ]);
    granted(&f.ask(&compose(), COMPOSE), "tok_1");
    f.clock.advance(3299);
    granted(&f.ask(&compose(), COMPOSE), "tok_1");
    f.clock.advance(1);
    granted(&f.ask(&compose(), COMPOSE), "tok_2");
    let lines: Vec<String> = f.requests().iter().map(|r| r.line()).collect();
    assert_eq!(
        lines,
        [
            "POST /api/auth/apps/token",
            "GET /api/auth/me",
            "POST /api/auth/apps/token"
        ]
    );
}

#[test]
fn a_cached_session_is_answered_when_the_server_cannot_say() {
    let mut f = Fixture::signed_in(vec![
        (200, Fixture::minted("tok_1", 86_400)),
        (503, String::new()),
    ]);
    granted(&f.ask(&compose(), COMPOSE), "tok_1");
    granted(&f.ask(&compose(), COMPOSE), "tok_1");
    assert_eq!(f.requests().len(), 2);
}

#[test]
fn each_caller_has_its_own_session() {
    let mut f = Fixture::signed_in(vec![
        (200, Fixture::minted("tok_firefox", 86_400)),
        (200, Fixture::minted("tok_chromium", 86_400)),
        (200, Fixture::minted("tok_mail", 86_400)),
    ]);
    granted(&f.ask(&firefox(), BROWSER), "tok_firefox");
    granted(
        &f.ask(&system_app("org.chromium.Chromium"), BROWSER),
        "tok_chromium",
    );
    granted(
        &f.ask(
            &system_app("com.mauvely.mail"),
            r#"{"v":1,"op":"token","client":"mail"}"#,
        ),
        "tok_mail",
    );
    let reqs = f.requests();
    // The broker names the browser; the caller cannot.
    assert_eq!(
        reqs[0].json(),
        serde_json::json!({"deviceLabel":"Firefox on testhost"})
    );
    assert_eq!(
        reqs[1].json(),
        serde_json::json!({"deviceLabel":"Chromium on testhost"})
    );
    assert_eq!(reqs[2].json(), serde_json::json!({"client":"mail"}));
}

#[test]
fn a_401_ends_the_link_and_offers_it_again() {
    let mut f = Fixture::signed_in(vec![
        (200, Fixture::minted("tok_1", 86_400)),
        (401, error("unauthorized")),
    ]);
    granted(&f.ask(&compose(), COMPOSE), "tok_1");
    refused(&f.ask(&firefox(), BROWSER), "signed_out");
    assert!(f.stored().is_none(), "the os session is forgotten");
    assert!(!f.store.exists());
    assert_eq!(f.offers(), 1);
    // And what was minted from it is not answered any more.
    refused(&f.ask(&compose(), COMPOSE), "signed_out");
    assert_eq!(f.requests().len(), 2);
}

#[test]
fn a_session_linked_to_another_server_is_dropped() {
    // /etc/mauvely/server changed, or the origin was pointed elsewhere: the
    // 90-day token is not sent to the new one.
    let elsewhere = OsSession {
        token: OS_TOKEN.into(),
        expires_at: NOW + 86_400,
        email: "ada@example.com".into(),
        origin: "https://mauvely.dev".into(),
    };
    let mut f = Fixture::with(vec![], Some(elsewhere));
    assert!(!f.store.exists());
    f.broker.offer_if_wanted();
    assert_eq!(f.offers(), 1);
    refused(&f.ask(&compose(), COMPOSE), "signed_out");
    assert!(f.requests().is_empty());

    // Sealed before origins were (no field): the same.
    let mut f = Fixture::with(
        vec![],
        Some(OsSession {
            origin: String::new(),
            ..f_session()
        }),
    );
    assert!(!f.store.exists());
    refused(&f.ask(&compose(), COMPOSE), "signed_out");
    assert!(f.requests().is_empty());
}

fn f_session() -> OsSession {
    OsSession {
        token: OS_TOKEN.into(),
        expires_at: NOW + 86_400,
        email: "ada@example.com".into(),
        origin: "{BASE}".into(),
    }
}

#[test]
fn a_session_the_organisation_turned_off_is_not_answered_again() {
    // /api/auth/me refuses an app the organisation withdrew; the mint then
    // says why.
    let mut f = Fixture::signed_in(vec![
        (200, Fixture::minted("tok_1", 86_400)),
        (403, error("app_not_allowed")),
        (403, error("app_not_allowed")),
    ]);
    granted(&f.ask(&compose(), COMPOSE), "tok_1");
    refused(&f.ask(&compose(), COMPOSE), "app_not_allowed");
    let lines: Vec<String> = f.requests().iter().map(|r| r.line()).collect();
    assert_eq!(
        lines,
        [
            "POST /api/auth/apps/token",
            "GET /api/auth/me",
            "POST /api/auth/apps/token"
        ]
    );
}

#[test]
fn an_expired_os_session_is_dropped() {
    // Expired before this login.
    let old = OsSession {
        expires_at: NOW - 1,
        ..f_session()
    };
    let mut f = Fixture::with(vec![], Some(old));
    assert!(!f.store.exists());
    f.broker.offer_if_wanted();
    assert_eq!(f.offers(), 1);
    refused(&f.ask(&compose(), COMPOSE), "signed_out");
    assert!(f.requests().is_empty());

    // Expires during it.
    let mut f = Fixture::signed_in(vec![]);
    f.clock.advance(86_400);
    refused(&f.ask(&compose(), COMPOSE), "signed_out");
    assert!(!f.store.exists());
    assert_eq!(f.offers(), 1);
    assert!(f.requests().is_empty());
}

#[test]
fn single_sign_on_is_passed_on_and_the_link_kept() {
    let body = r#"{"error":{"code":"sso_required","message":"Your organisation signs you in with single sign-on.",
        "org":"northgate","start":"/api/auth/sso/start?org=northgate"},"requestId":"r1"}"#;
    let mut f = Fixture::signed_in(vec![(403, body.into())]);
    let a = f.ask(&firefox(), BROWSER);
    refused(&a, "sso_required");
    assert_eq!(a["org"], "northgate");
    assert_eq!(
        a["start"],
        format!("{}/api/auth/sso/start?org=northgate", f.base)
    );
    assert!(f.stored().is_some());
    assert_eq!(f.offers(), 0);
    assert_eq!(f.requests().len(), 1);
}

#[test]
fn server_refusals_are_passed_on() {
    for (status, body, reason) in [
        (403, error("app_not_allowed"), "app_not_allowed"),
        (403, error("forbidden"), "refused"),
        (429, error("rate_limited"), "rate_limited"),
        (500, String::new(), "unreachable"),
        (200, "{}".into(), "bad_response"),
    ] {
        let mut f = Fixture::signed_in(vec![(status, body)]);
        refused(&f.ask(&compose(), COMPOSE), reason);
        assert!(f.stored().is_some(), "{reason}: the link is kept");
        assert_eq!(f.requests().len(), 1);
    }
    // Nothing listening: unreachable, and nothing is cached.
    let f = Fixture::signed_in(vec![]);
    refused(&f.ask(&compose(), COMPOSE), "unreachable");
}

/// The browser extension's first question, so it knows which cookie to look
/// for. Answered signed in or not, without the server, and only to a browser.
#[test]
fn the_origin_is_told_to_the_browsers_alone() {
    for mut f in [Fixture::new(vec![]), Fixture::signed_in(vec![])] {
        for browser in [firefox(), system_app("org.chromium.Chromium")] {
            let a = f.ask(&browser, ORIGIN);
            assert_eq!(
                a,
                serde_json::json!({"v":1,"ok":true,"origin":f.base}),
                "{a}"
            );
        }
        for caller in [
            compose(),
            super::caller::Caller::Host,
            super::caller::Caller::Unknown("exited".into()),
            system_app("org.mozilla.Firefox"),
        ] {
            refused(&f.ask(&caller, ORIGIN), "forbidden");
        }
        assert!(f.requests().is_empty());
    }
}

#[test]
fn refused_callers_cost_nothing() {
    let mut f = Fixture::signed_in(vec![]);
    let home = super::caller::Caller::Sandbox(super::caller::Sandbox {
        app: "org.mozilla.firefox".into(),
        app_path: "/home/ada/.local/share/flatpak/app/org.mozilla.firefox/x86_64/stable/c/files"
            .into(),
        app_mounted: true,
        origin: Some("flathub".into()),
    });
    for (caller, line, reason) in [
        (super::caller::Caller::Host, COMPOSE, "forbidden"),
        (super::caller::Caller::Host, BROWSER, "forbidden"),
        (
            super::caller::Caller::Unknown("exited".into()),
            BROWSER,
            "forbidden",
        ),
        (home, BROWSER, "forbidden"),
        (compose(), BROWSER, "forbidden"),
        (firefox(), COMPOSE, "forbidden"),
        (
            compose(),
            r#"{"v":1,"op":"token","client":"mail"}"#,
            "forbidden",
        ),
        (
            compose(),
            r#"{"v":1,"op":"token","client":"suite"}"#,
            "unknown_client",
        ),
        (compose(), r#"{"v":1,"op":"cloud-link"}"#, "unknown_op"),
        (compose(), r#"{"v":2,"op":"token"}"#, "version"),
    ] {
        refused(&f.ask(&caller, line), reason);
    }
    assert!(f.requests().is_empty());
}

#[test]
fn two_callers_at_once_get_one_mint() {
    let mut f = Fixture::signed_in(vec![
        (200, Fixture::minted("tok_1", 86_400)),
        (200, ALIVE.into()),
    ]);
    let broker = Arc::clone(&f.broker);
    let other = std::thread::spawn(move || broker.answer(&compose(), COMPOSE.as_bytes()));
    let mine = f.ask(&compose(), COMPOSE);
    let theirs: serde_json::Value = serde_json::from_slice(&other.join().unwrap()).unwrap();
    granted(&mine, "tok_1");
    granted(&theirs, "tok_1");
    let lines: Vec<String> = f.requests().iter().map(|r| r.line()).collect();
    assert_eq!(lines, ["POST /api/auth/apps/token", "GET /api/auth/me"]);
}

#[test]
fn after_a_sign_out_a_new_link_mints_afresh() {
    let mut f = Fixture::signed_in(vec![
        (200, Fixture::minted("tok_1", 86_400)),
        (401, error("unauthorized")),
        start(5, 600),
        (200, Fixture::minted("tok_os_2", 90 * 86_400)),
        (200, Fixture::minted("tok_2", 86_400)),
    ]);
    granted(&f.ask(&compose(), COMPOSE), "tok_1");
    refused(&f.ask(&firefox(), BROWSER), "signed_out");
    f.broker.link();
    assert_eq!(f.stored().unwrap().token, "tok_os_2");
    // Not tok_1 from before: minted again, as the new session.
    granted(&f.ask(&compose(), COMPOSE), "tok_2");
    let reqs = f.requests();
    assert_eq!(reqs[4].line(), "POST /api/auth/apps/token");
    assert_eq!(reqs[4].header("Authorization"), Some("Bearer tok_os_2"));
}

#[test]
fn signed_in_a_sign_in_click_does_nothing() {
    let mut f = Fixture::signed_in(vec![]);
    f.broker.link();
    assert!(f.desktop.opened.lock().unwrap().is_empty());
    assert!(f.requests().is_empty());
}

#[test]
fn once_a_link_starts_the_offer_no_longer_asks_first() {
    let f = Fixture::new(vec![
        (503, String::new()),
        start(5, 600),
        (200, Fixture::minted("tok_os_new", 90 * 86_400)),
        (401, error("unauthorized")),
    ]);
    f.broker.offer_if_wanted();
    f.broker.link();
    f.broker.link();
    assert_eq!(f.stored().unwrap().token, "tok_os_new");
    // Signed out later: the window may link by itself again.
    refused(&f.ask(&compose(), COMPOSE), "signed_out");
    assert_eq!(*f.desktop.asks.lock().unwrap(), [false, true, false]);
}

/// The person closes the sign-in window as soon as the code is shown.
fn close_on_show(f: &Fixture) {
    let broker = Arc::downgrade(&f.broker);
    *f.desktop.on_show.lock().unwrap() = Some(Box::new(move || {
        broker.upgrade().unwrap().closed();
    }));
}

#[test]
fn closing_the_window_ends_the_link_after_one_more_poll() {
    let mut f = Fixture::new(vec![start(5, 600), pending(), pending()]);
    close_on_show(&f);
    f.broker.offer_if_wanted();
    f.broker.link();
    assert!(f.stored().is_none());
    assert_eq!(f.desktop.withdrawn.load(Ordering::SeqCst), 1);
    // Later: not offered again until the next login.
    f.broker.offer_if_wanted();
    assert_eq!(f.offers(), 1);
    let lines: Vec<String> = f.requests().iter().map(|r| r.line()).collect();
    assert_eq!(
        lines,
        ["POST /api/auth/device/start", "POST /api/auth/device/token"]
    );
}

#[test]
fn a_link_approved_just_before_the_window_closed_is_still_claimed() {
    let mut f = Fixture::new(vec![
        start(5, 600),
        (200, Fixture::minted("tok_os_new", 90 * 86_400)),
    ]);
    close_on_show(&f);
    f.broker.link();
    assert_eq!(f.stored().unwrap().token, "tok_os_new");
    // Claimed, then the window is told it may sign its own session out.
    assert_eq!(*f.desktop.signed_in.lock().unwrap(), ["ada@example.com"]);
    assert_eq!(f.desktop.withdrawn.load(Ordering::SeqCst), 0);
    assert_eq!(f.requests().len(), 2);
}

fn login_session(origin: &str, lifetime: u64) -> OsSession {
    OsSession {
        token: "tok_login".into(),
        expires_at: NOW + lifetime,
        email: "ada@example.com".into(),
        origin: origin.into(),
    }
}

#[test]
fn without_a_login_session_or_a_link_the_link_is_offered() {
    assert!(FakeLogin(None).session().is_none());
    let f = Fixture::new(vec![]);
    f.broker.offer_if_wanted();
    assert_eq!(f.offers(), 1);
}

#[test]
fn a_session_from_the_login_needs_no_link() {
    let mut f = Fixture::with_login(
        vec![(200, Fixture::minted("tok_compose", 3600))],
        None,
        Some(login_session("{BASE}", 3600)),
    );
    // Nothing is shown: no window, no question.
    f.broker.offer_if_wanted();
    assert_eq!(f.offers(), 0);
    granted(&f.ask(&compose(), COMPOSE), "tok_compose");
    let reqs = f.requests();
    assert_eq!(reqs[0].header("Authorization"), Some("Bearer tok_login"));
    // Sealed as a linked session is, for the next start of the helper.
    assert_eq!(f.stored().unwrap().token, "tok_login");
}

#[test]
fn a_session_from_the_login_replaces_the_stored_one() {
    // The login revoked the one the last login made here, so the stored
    // session is the older, and the login's is used and kept.
    let stored = OsSession {
        token: OS_TOKEN.into(),
        expires_at: NOW + 86_400,
        email: "ada@example.com".into(),
        origin: "{BASE}".into(),
    };
    let mut f = Fixture::with_login(
        vec![(200, Fixture::minted("tok_compose", 3600))],
        Some(stored),
        Some(login_session("{BASE}", 3600)),
    );
    f.broker.offer_if_wanted();
    assert_eq!(f.offers(), 0);
    granted(&f.ask(&compose(), COMPOSE), "tok_compose");
    assert_eq!(
        f.requests()[0].header("Authorization"),
        Some("Bearer tok_login")
    );
    assert_eq!(f.stored().unwrap().token, "tok_login");
}

#[test]
fn a_login_session_for_another_server_or_expired_is_not_taken() {
    for login in [
        login_session("https://other.example", 3600),
        login_session("{BASE}", 0),
    ] {
        let mut f = Fixture::with_login(vec![], None, Some(login.clone()));
        f.broker.offer_if_wanted();
        assert_eq!(f.offers(), 1);
        refused(&f.ask(&compose(), COMPOSE), "signed_out");
        assert!(f.requests().is_empty());
        assert!(f.stored().is_none());

        // And a stored session is still used.
        let stored = OsSession {
            token: OS_TOKEN.into(),
            expires_at: NOW + 86_400,
            email: "ada@example.com".into(),
            origin: "{BASE}".into(),
        };
        let mut f = Fixture::with_login(
            vec![(200, Fixture::minted("tok_compose", 3600))],
            Some(stored),
            Some(login),
        );
        f.broker.offer_if_wanted();
        assert_eq!(f.offers(), 0);
        granted(&f.ask(&compose(), COMPOSE), "tok_compose");
        assert_eq!(
            f.requests()[0].header("Authorization"),
            Some(format!("Bearer {OS_TOKEN}").as_str())
        );
    }
}
