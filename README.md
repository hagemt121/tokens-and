# tokens-and

A small Go bridge from security scanner findings to Spotify playback. Semgrep and gosec JSON reports are normalized into `signal.Finding` values and sent through a Go channel. The example CLI logs matching findings and can pause Spotify once when a report contains findings at or above a severity threshold.

## Run

Requires Go 1.27.1 or newer. The module uses `golang.org/x/oauth2`, `golang.org/x/sync`, and `golang.org/x/time`.

`make demo` runs Semgrep against the current project with the `p/security-audit` ruleset, sends its JSON findings through a Go channel, and prints the findings and total. It uses `SEMGREP_CLI` when set, then `/opt/homebrew/bin/semgrep` or `semgrep` on `PATH`. The ruleset may require access to Semgrep's registry.

To run Semgrep from the app:

```sh
go run ./cmd/tokens-and -scan -semgrep-config p/security-audit -target .
```

`SEMGREP_CLI` overrides the Semgrep executable used by `-scan`. When unset, the app tries `/opt/homebrew/bin/semgrep` first, then `semgrep` on `PATH`. For example, `SEMGREP_CLI=/usr/local/bin/semgrep go run ./cmd/tokens-and -scan`. Scan mode uses the Semgrep report channel path below. The app also accepts reports produced separately:

```sh
semgrep scan --config p/security-audit --json --output semgrep.json .
go run ./cmd/tokens-and -scanner semgrep -report semgrep.json
```

```sh
gosec -fmt json -out gosec.json ./...
go run ./cmd/tokens-and -scanner gosec -report gosec.json
```

The scanner may exit with a nonzero status when it finds issues; its JSON report can still be passed to the bridge. Use `-report -` to read JSON from standard input. The default action is `log`, so the examples make no Spotify request. The default threshold is `HIGH`; set `-min-severity LOW|MEDIUM|HIGH|CRITICAL` to change it.

To authorize Spotify, register `http://127.0.0.1:8888/callback` as a redirect URI in the Spotify developer dashboard, set your app's client ID, then open the URL printed by the login command:

```sh
export SPOTIFY_CLIENT_ID='your-client-id'
go run ./cmd/tokens-and spotify-login
go run ./cmd/tokens-and -scanner semgrep -report semgrep.json -action pause
```

The login uses OAuth authorization code with PKCE and requests `user-modify-playback-state`. It saves the user token with file mode `0600` under your user config directory at `tokens-and/spotify.json`. Set `SPOTIFY_TOKEN_FILE` to choose another path, or `SPOTIFY_REDIRECT_URI` to use another registered `http://127.0.0.1:PORT/path` callback. Playback refreshes an expired access token and saves any rotated refresh token. Spotify refresh tokens can expire after six months, at which point you must run `spotify-login` again. `SPOTIFY_ACCESS_TOKEN` still works as a temporary manual override. Spotify's pause endpoint requires Premium and an active playback device. The CLI pauses at most once per report.

## Slack reporting daemon

Create a Slack app with a bot token that has `chat:write` and `im:write`. Set a workspace user ID for the tool administrator. The daemon opens a DM with that user and posts each finding at or above its severity threshold. To look up the user ID by email, grant `users:read` and `users:read.email` and run:

```sh
export SLACK_BOT_TOKEN='xoxb-...'
go run ./cmd/tokens-and lookup-user -workspace T12345678 -email admin@example.com
```

The lookup checks that the token belongs to the requested workspace, then prints the user ID. The daemon can also send to a channel ID by setting `SLACK_CHANNEL_ID` instead of `SLACK_ADMIN_USER_ID`; the bot must have access to that channel.

Start the daemon and send a scanner report to it from another process:

```sh
export SIGNAL_API_TOKEN='a-long-random-shared-secret'
export SLACK_ADMIN_USER_ID='U12345678'
go run ./cmd/tokens-and-daemon -listen 127.0.0.1:8787
```

```sh
export SIGNAL_API_TOKEN='the-same-shared-secret'
go run ./cmd/tokens-and -scanner semgrep -report semgrep.json -daemon-url http://127.0.0.1:8787
```

The `services.Bus` owns a shared `chan signal.Finding` and exposes `POST /signals` for authenticated JSON submissions. A successful HTTP response means the finding entered the in-memory queue; Slack delivery errors are logged by the daemon. The queue does not persist across restarts. The daemon binds to localhost by default; use TLS when exposing the endpoint across machines.

The daemon uses `errgroup` to coordinate the HTTP server, signal worker, and shutdown. Slack sends are spaced to one per second by `rate.Limiter`; the queue absorbs short bursts.

## Channel integration

The packages `semgrepcli`, `services`, `signal`, `slack`, and `spotify` live under `internal/` while their APIs are evolving. The demo and CLIs can import them from this module. The `signal.Finding` type is the channel contract. A tool that already produces findings in Go can send them directly:

```go
findings := make(chan signal.Finding)
go func() {
    defer close(findings)
    findings <- signal.Finding{
        Source: "custom", RuleID: "SEC-001", Severity: "HIGH",
        Message: "Example issue", Path: "main.go", Line: "12",
    }
}()
for finding := range findings {
    // Apply your own threshold and Spotify action here.
    _ = finding
}
```

`signal.Decode("semgrep", reader, findings)` and `signal.Decode("gosec", reader, findings)` adapt complete JSON reports into the same channel. The caller closes the channel after decoding. Gosec findings marked `nosec` or carrying suppressions are skipped. Semgrep's `ERROR`, `WARNING`, and `INFO` map to `HIGH`, `MEDIUM`, and `LOW` in this starter.

## Verify

```sh
go test ./...
```

Scanner and API details: [Semgrep JSON fields](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif), [gosec JSON output](https://github.com/securego/gosec), [Spotify PKCE](https://developer.spotify.com/documentation/web-api/tutorials/code-pkce-flow), [Spotify token refresh](https://developer.spotify.com/documentation/web-api/tutorials/refreshing-tokens), [Spotify pause playback](https://developer.spotify.com/documentation/web-api/reference/pause-a-users-playback), [Slack DM opening](https://docs.slack.dev/reference/methods/conversations.open/), [Slack user lookup](https://docs.slack.dev/reference/methods/users.lookupByEmail/).
