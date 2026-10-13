# Mauvely OS agent

`mauvelyd` is the on-device daemon for Mauvely OS. It:
- enrols the device with the management server;
- checks in;
- installs and removes Flatpaks;
- stages image updates.

The login modules `pam_mauvely` and `nss_mauvely` follow in milestone 2. They
talk only to the daemon over a local socket, never to the network.

Written in Rust. Licensed under the GNU GPL, version 3 or later.
