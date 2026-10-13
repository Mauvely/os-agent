# os-agent

`mauvelyd`, the Mauvely OS device agent, in Rust.

The design and the frozen agent API (enrolment, signed check-ins) are in brief
19: `Website/website-internal/docs/launch/plans/19-mauvely-os.md` in the
Mauvely superproject.

- **The server side** is `Website/website-devices`.
- **The signing vectors** in `tests/vectors/` are shared with it. Change both
  sides together.

## Rules

- **The daemon runs as root.** Every external command goes through a trait, so
  it can be faked in tests: `flatpak`, `bootc`, `systemd-creds`. Never shell
  out with an interpolated string.
- **PAM and NSS modules never touch the network** (milestone 2). They talk to
  the daemon over its socket, and they fail fast and closed when it does not
  answer.
- **Never log a device key or an enrolment token.**
- **`cargo test` must pass** without root, a TPM, flatpak or network.

## Handing off

`HANDOFF.md` is overwritten each session. It holds what is half-done, what was
tried and rejected, and what compiles but has never run.
