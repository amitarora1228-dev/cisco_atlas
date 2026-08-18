# Changelog

Every change to ATLAS is recorded here before it is committed. This is a record
of *what changed and why it mattered*, written for someone who was not in the
room - not a restatement of the diff.

Entries state measured numbers, never estimates, and record what was **verified**
rather than what was intended. A change that was not checked against reality says
so.

For current status, known limitations and traps, see [`docs/STATE.md`](docs/STATE.md).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet publish versioned releases, so changes are grouped
under `[Unreleased]` until one is cut.

---

## [Unreleased]

### Fixed

- **`run.ps1` could not start ATLAS on a clean virtualenv.** The script probes
  for the superseded `python-evtx` package by importing it, and that import is
  *meant* to fail once the venv is clean. But the script sets
  `ErrorActionPreference = "Stop"`, and under PowerShell 5.1 a native command
  writing anything to stderr raises a terminating `NativeCommandError` — so the
  probe's own traceback aborted the launcher at that line, before the server
  ever started. Neither `2>$null` nor `2>&1 | Out-Null` suppresses it.

  The effect was backwards: the launcher worked only while the obsolete package
  was still installed, and broke as soon as the cleanup it performs had
  succeeded. The preference is now relaxed for the probe alone and only the exit
  code is read. Verified by starting the server on a clean venv.

### Added

- **The flow table can be pinned to one traffic channel.** Every flow already
  carried a channel — DNS, WEB, QUIC or NET — and the badge was visible on each
  row, but there was no way to act on it: the only filters were free text and
  "show only problems". Reading a capture usually means reading one channel at a
  time, so the channels are now buttons, each carrying its own count.

  The counts are taken before any filter is applied, so they keep saying how
  much traffic each channel carried rather than how much survived the current
  view. A capture with a single channel shows no buttons at all, because
  offering to filter by the only thing present is noise.

  The empty-state text was wrong and is now specific. It blamed "show only
  problems" whatever had actually emptied the table, so a search that matched
  nothing produced a sentence about a toggle the reader had not touched.

- **A DNS flow now says what it asked for and what came back.** It already
  carried a `DNS query` badge and then told you nothing: not the name, not the
  answer. The reason is worth recording, because it looks like an oversight and
  is not. `_correlate_dns_to_flows` keys lookups by *destination address*, which
  is how an IP-only connection gets tied back to the hostname that produced it.
  A DNS conversation's destination is the resolver, so that correlation runs in
  the wrong direction and leaves the flow with nothing to attach.

  The lookups a flow carries are now read from the flow itself. Queries and
  replies are paired by transaction ID (RFC 1035 §4.1.1), which is what makes a
  request and its answer one exchange rather than two unrelated events, and the
  DNS layer of the connection story reports each name with the addresses it
  resolved to, the CNAME chain it travelled, and the resolver that answered.

  Two things it deliberately does not do. It does not claim `A` for every query:
  the type is read and named, which is how a set of ISE captures turned out to
  be asking for `HTTPS` records (RFC 9460) all along. And it does not flag an
  empty `AAAA` reply, because a name with no IPv6 address answering NODATA is
  ordinary rather than a fault — the first draft called that a warning on every
  IPv4-only name in the capture.

  Bounded at twelve exchanges per flow so a busy resolver conversation cannot
  grow the payload without limit. Ten tests.

- **The detection engine was cross-examined against tshark, and the result is
  written down.** A hundred and two checks across four harnesses
  (`tools/_validate_*.py`) re-derive independently what the engine claims: TCP
  and TLS counters, the interpretive calls about direction and blame, the
  rule-based findings, and the deep work — inner-tunnel TLS, certificate
  issuers, JA3/JA3S, ECH, ALPN, CONNECT targets. All 102 agree, on 46,884
  packets across three captures.

  Thirteen checks failed on the way there. **Twelve were defects in the harness,
  not in the engine**, and two of those are worth keeping because they look like
  bugs and are not. The inner SNI does not match the CONNECT target in the DLP
  capture, because all 178 CONNECT lines name an *address* — the client resolved
  the name itself, and recovering `claude.ai` from inside the tunnel is the
  entire point of the second pass. And certificate issuers come from parsing the
  DER, so the engine reports names that `tshark -e x509sat.*` never exposes;
  ground truth for that has to be the full `-V` dissection. A third was simply
  wrong arithmetic on my part: `tcp.analysis.initial_rtt` is attached to every
  frame of a stream, so taking a median over frames weights it by whichever flow
  carried the most packets. Deduplicated by stream, engine and tshark agree
  exactly — 585, 75 and 11 flows, identical medians.

  **The thirteenth was real.** `analyze_dns` keeps one record per name, so when
  the roaming module on `127.0.0.1` answered `malware.com` with NXDOMAIN and
  `8.8.8.8` answered the same name with SERVFAIL, only SERVFAIL survived. The
  disagreement between the two resolvers *is* the diagnosis — it shows the local
  module blocking a name the external resolver did not — and the model discards
  it. Recorded in `VALIDATION_GAPS.md` §2.11 rather than patched, because keying
  records by (name, resolver) changes the DNS model and the views built on it.

  The harnesses are committed rather than described, so the claim can be
  re-checked instead of believed.

### Changed

- **`VALIDATION_GAPS.md` now separates what was measured from what was
  reasoned.** The document already carried an honesty rule; what it lacked was
  evidence. It now records the 95 checks, an end-to-end plan sequenced so each
  stage is provable before the next begins, and a deferred list that names, for
  every blocked item, the exact capture or key log that would unblock it.

  Three measured findings were added that the document did not have:

  **The latency thresholds cannot fire.** Across 810 flows in three captures
  they produced zero findings — the constants sit 7–25x above the p95 of every
  capture we hold. Being absolute they are also too *low* for a satellite or
  long-haul link, where a 400 ms median would make every flow fire. They are
  currently decoration.

  **Six signal families are in our captures and we walk past them.** Counted,
  not assumed: 919 TCP window-scale options (without which the window we print
  is wrong by up to 2^14), 76 SACK blocks, 60 session tickets, 16 OCSP stapling
  requests, 4 HTTPS/SVCB records — the record that carries ECH configuration and
  therefore the mechanism that will one day hide the SNI from Secure Access —
  and 12 DNS queries over TCP.

  **Eleven of 69 detectors have never executed.** Including expired
  certificates, name mismatch and TLS alerts. Their first real run would
  otherwise be at a customer.

  A web-layer gap list was added with the standards behind each item, and two
  quiet corrections: ECH is still `draft-ietf-tls-esni`, not an RFC, and WPAD
  was never standardised at all — its draft expired in 1999.

- **The correlation view tells the same story as the capture view.** It was
  still drawing the old packet ladder - `SYN`, `ACK`, `Data 517B` - which says
  that bytes moved but not what they were, so the layer that failed was left for
  the reader to work out. The obstacle was real: correlation is built on
  `WireFlow`, a deliberately summarised model held for every flow in a session,
  and it carried only five packet kinds. Enriching it was chosen over faking it.

  Seven fields were added to the **same single tshark pass**, and the summaries
  they feed are capped rather than per-packet - at most 12 handshake names, 8
  statuses, 4 ALPN tokens - so the model does not grow with traffic. Packet
  kinds went from 5 to 12, adding `clienthello`, `serverhello`, `certificate`,
  `clientkeyexchange`, `alert`, `http_request` and `http_response`. Measured on
  a 937-flow capture, the story now covers TCP on **937** flows, the transfer on
  489, TLS on 232, the tunnel on 178 and plain HTTP on 8.

  It reports no DNS layer, and says why: this pass filters on TCP and name
  resolution is UDP. A silently missing layer would read as a clean lookup.

  Caught while building it: reading the negotiated version from
  `tls.handshake.version` would have labelled **every** TLS 1.3 session as 1.2,
  because 1.3 pins that legacy field at `0x0303` for middlebox compatibility.
  The version now comes from the `supported_versions` extension, and the count
  agrees exactly with what the capture engine reports independently - 166 and
  166. The field name was verified against tshark first, since one unknown `-e`
  aborts the entire run rather than degrading.

- **A HAR entry now shows what the file actually recorded.** The detail view
  displayed **11** fields; the API was already sending 45. The phase timings in
  particular were parsed, transported and never drawn. It now shows **30**
  fields plus a proportional phase chart, adding why the browser made the
  request, the resource type, referer and origin, the redirect target, who
  served it, the decoded body size and compression ratio, what was uploaded,
  header counts, caching and whether credentials were sent.

  Nothing was being dropped at parse time, which is worth recording because it
  was the first suspicion: 302 of 302 entries and 15 of 15 in the two test
  files. What varies is the exporter, not the parser. A browser export carries
  the full phase breakdown (14 of 15 entries); a proxy-side export carries none
  (0 of 302). Where the phases are absent the view says so and names the reason,
  rather than leaving the block empty.

### Fixed

- **The HAR phase chart counted the TLS handshake twice.** Charting `connect`
  and `ssl` as siblings put a connect segment and a TLS segment of near
  identical length side by side - 139.2 ms and 137.9 ms on one request - because
  the HAR spec measures `ssl` *inside* `connect`. Subtracting gives the honest
  split, and it inverts the reading: that request spent **1.3 ms** opening the
  socket and **137.9 ms** in the handshake.

### Added

- **Every connection now tells its story in the order it had to succeed.** The
  packet ladder said *what* crossed the wire; nobody was reading it, because a
  list of SYNs and ACKs does not say which layer failed. The same events are now
  grouped into DNS, TCP, TUNNEL, TLS, HTTP and DATA, each with its own verdict
  and the measurements the engine already had, and closed by a conclusion that
  names the layer that broke. Every step carries its frame number so any claim
  can be checked in Wireshark. Measured on a 20 MB capture: 1,603 stories, and
  of 7,701 measurements emitted 6,414 are neutral, 1,259 are warnings and only
  **28** are marked as problems - a healthy layer stays quiet rather than
  padding the page with zeroes.

  Validating it against real traffic found the logic blaming the wrong party.
  The first version read an ACK before a reset as proof the *server* had refused,
  and said so even when the server had answered with its ServerHello and the
  *client* was the one that sent the reset: **51 of 55** flows in the test
  capture were attributed backwards, and the steps were printed out of
  chronological order, which is the whole argument. Direction is now read from
  the reset itself. A client reset after a ServerHello says the client rejected
  what it was shown - most often the certificate - and the text says that this
  proves the timing, not the motive.

- **Traffic that misbehaves inside an opaque tunnel is now reported, without a
  cause being invented.** A CONNECT tunnel carrying TLS is opaque by design, so
  the analyzer had only two habits: stay silent or guess. On a capture of a
  YouTube session that never played, it stayed silent - **0 of 121** flows were
  marked as having a problem, the worst severity in the whole file was `low`,
  and the headline diagnosis was an mDNS lookup for a printer.

  Four conditions together now raise a `high` finding: the tunnel was
  established (CONNECT 2xx), less came back than went out, it was abandoned
  without being closed, and at least three of them were opened to one service
  within ten seconds. Each alone is ordinary traffic. On that capture: 3 tunnels
  to 3 googlevideo endpoints in 0.3 s, **24,380 bytes returned for 82,115 sent**,
  each dropped within 1.6 s. The finding states the pattern, says plainly that
  the status code and the error are encrypted so rejection, throttling and the
  client giving up cannot be told apart, lists what the capture *did* rule out,
  and gives the three steps that would settle it. It names no root cause.

### Fixed

- **A certificate was called expired for having aged since the capture.** The
  check compared `not_after` against `datetime.now()`, which answers a different
  question from the one being asked: whether the certificate held *when the
  traffic happened*. Every capture eventually ages past the certificates in it,
  so old files turned into certificate incidents. Measured across the two test
  captures, **all 16** such findings were wrong - `client.wns.windows.com` was
  reported at `high` severity for expiring on 2026-03-09 in traffic captured on
  **2026-03-06**, three days before it lapsed. All 63 certificates in those
  captures were valid at the moment they were presented.

  The reasoning also lived in four places - the findings engine, the connection
  story, the text report and the API payload - and all four had the same defect,
  which is how the bug survived being fixed once. There is now a single
  `evaluate_at(cert, when)` in `certs.py`, and `CertInfo.expired` /
  `not_yet_valid` were **removed** rather than deprecated: a field named
  `expired` invites the next reader to believe it means "expired then". Without
  a moment to judge against, the answer is `unknown` - never a silent fall back
  to now.

- **Certificates were flagged for having little life left.** Fourteen flows were
  marked amber for expiring within 14 days. All fourteen were proxy-minted
  certificates with a **five-day** total lifetime, so one day remaining is that
  design working as intended; the threshold had been written for year-long
  public certificates, of which the same capture held 49 at 1,095 days. Time
  remaining cannot be read without knowing the issuing policy, so it is no
  longer reported at all. Only a certificate outside its window at the time of
  the connection is marked.

- **The error column led with capture artefacts instead of the diagnosis.** A
  flow whose finding was "tunnel opened, then abandoned" showed
  `25 packet(s) sent again; 2 packet(s) arrived out of order` - counts already
  known to be inflated by the same traffic being recorded on three interfaces,
  and whose *findings* the analyzer had correctly suppressed. The raw counters
  were still printed, and first. The diagnosis now leads and the counters follow.

- **A capture-wide finding left every flow looking healthy.** `has_problem` is
  computed only from a flow's own findings, so a finding about a group of
  connections marked none of them and an "errors only" view showed nothing -
  precisely the silence the finding exists to break. A pattern now marks every
  connection it covers, not just the first.

### Changed

- **The packet-by-packet ladder is hidden.** The connection story is the reading
  of the same events, so the raw sequence diagram is behind
  `SHOW_PACKET_LADDER`, set to `false`. Set it to `true` to bring it back.

### Changed

- **The path stitcher no longer compares every connection against every other.**
  Asked how many files the path view accepts, the answer turned out not to be
  about files at all: file count is linear at about 0.33 s each (80 files in
  26.3 s, dominated by tshark startup), but the link-building loop was quadratic
  in the number of *connections* across all of them. Measured: 4,000
  connections 3.15 s, 8,000 **13.6 s**, 16,000 **54.4 s** - and a capture from a
  busy firewall reaches those numbers easily. Both joins are equality tests, so
  the candidates are now looked up by source address and by SNI instead of
  searched for. Measured after: 8,000 in **0.06 s** (227x), 16,000 in **0.12 s**
  (453x), 64,000 in 0.70 s. Output on the real three-vantage path is byte for
  byte the same, and the four path tests still pass.

- **"Carried by" now says *why* no tunnel was named.** One label, "not
  identified", was standing for four different situations, which made a
  question that has an answer look like one that does not. Measured on the
  session in hand (385 flows, 269 joined): 57 flows the agent never logged at
  all - named by the capture, so no stream exists to join on and none ever
  will; 38 where the agent recorded a stream no tunnel reports; 23 where
  several tunnels report that stream, because HTTP/2 stream numbers restart per
  connection and stream 1 alone appears 160 times in this log; 10 with no
  stream recorded. The cell now reads `agent silent`, `not in log`,
  `ambiguous` or `no stream`, with the full sentence as a tooltip and in the
  expanded row. The distinction matters because one of those is a permanent
  limit of the inputs and the others might be settled by a longer log.

### Fixed

- **The end-to-end path view could only ever hold one set of captures.** The
  input accepted multiple files, but a file input *replaces* its selection on
  every pick - and captures from different hops come from different machines,
  so they are chosen one at a time far more often than together. Picking the
  FTD capture silently discarded the client one, leaving a single vantage point
  and nothing to stitch. Selections now accumulate, are listed with their sizes
  and can be removed individually or cleared; duplicates are ignored and
  dropping files onto the view works. Verified: two files then a third gives
  three, re-adding the third leaves three, removing gives two.
- **Nothing preformatted was readable in the darker theme.** The bundle engine
  ships `input, textarea, select, pre { background: #fff !important; color:
  var(--text-main) !important }` - a hardcoded white background paired with a
  text colour that flips with the theme. In the darker theme `--text-main` is
  `#e6eaef`, so all **19 `<pre>` elements on the page measured a contrast ratio
  of 1.22** - the capture engine's report, the bundle output and the key-log
  help as well as the new report preview. Repaired with a darker-theme-scoped
  override that takes both colours from the same palette. Measured after:
  minimum contrast **6.36** across 25 elements in both themes, none below the
  4.5 accessibility floor.
- **Read Me, Feedback and the `?` popover did nothing from most views** - three
  reports, one cause. Each is reached from the shared header but its panel is
  owned by one engine, and an engine that is not the active one is
  `display:none`. The toggles were firing correctly the whole time; the panel
  un-hid into a hidden subtree and measured **0x0**. The three panels are now
  moved into a shell-owned overlay at startup, which keeps their listeners
  intact so neither engine's JavaScript changed. Verified from the Correlation
  view, where all three were previously dead: Read Me 900x673, Feedback
  900x576, help popover 360x262, each with a close control.
- **The avatar read `JM`** - hardcoded initials inherited from the capture
  engine. Now `A/J`, for Amit and Jairo, with the badge widened because three
  characters did not fit a 26px square with no padding.

### Added

- **The path view can be narrowed to one transaction** by address, port or
  hostname - one box, searched against every field, because an operator arrives
  knowing the resource as a hostname, or as the address the firewall logged, or
  as a port, and should not have to know which before they can search. The
  filter is applied to **finished chains, never to legs**: the obvious
  implementation would have destroyed the thing being asked for, since the
  client's first leg is addressed to the *proxy* and does not mention the
  resource at all, so filtering legs would leave the chain starting halfway
  along while still looking complete. Verified: focusing on `10.50.0.9`, named
  only by the last leg, returns both legs and still starts at the client;
  focusing by the client address or by source port works the same way; a term
  that matches nothing returns nothing and says how many it dropped. Two tests
  cover it, including the halfway-chain mistake.

- **Per-flow connection quality: round-trip time, jitter, retransmissions,
  duplicate ACKs, out-of-order and zero windows** - shown for the flow's own
  connection *and* for the tunnel carrying it, because in an intercepted
  session those are very different things. Three refusals are built in, each
  guarding against a number that would be believed:
  - **A local leg is not the network.** Measured on a real session, **62 of 62**
    flows with quality data ran to the agent's listener on 127.0.0.1. Their RTT
    is a memory copy - 0.02 ms - and reported as latency it would have made the
    session look flawless no matter how bad the path beyond the agent was.
    Those legs are flagged and their RTT is stated to be meaningless.
  - **Only the peer's ACKs measure a round trip.** Wireshark attaches `ack_rtt`
    to every ACK including the ones this machine sends, which are local and
    near-zero. Counting both gave a tunnel to a headend across the internet a
    median RTT of **0.333 ms**. Filtering to ACKs arriving from the peer took
    the sample count from 702 to 305 and the median to 0.766 ms, with a maximum
    of 73.7 ms - and even that is labelled a distribution rather than the
    path's latency, because ACK pairing under-reads whenever the sender bursts.
    The handshake RTT is named as the only clean measurement.
  - **Retransmissions are never converted into a loss percentage.** One capture
    point cannot tell a packet lost before it from one lost after it.

- **A Report view worth reading before you send it.** The report was previously
  a wall of text appended to the capture engine's page - everything or nothing,
  no preview, and a Download button that produced something the reader had not
  seen. It is now its own view: each section can be included or dropped with
  its size shown, the full text is rendered on screen, and Copy sits beside
  Download. The preview and the file come from the same call, so the report
  cannot promise something the view did not show. Measured on a real session:
  three sections (traffic capture 48 KB, endpoint bundle 377 KB, across
  artefacts 235 KB) making a 676,428-character report; dropping one section
  took it to 626,903.
- **History.** Every analysis is recorded when it finishes - time, files,
  hosts, flows, failing flows - so two runs can be compared without running one
  of them twice. Each record can be viewed, downloaded or deleted, with a
  delete-all. **Records live in this browser only and are never uploaded**, but
  they carry the hostnames and addresses from the evidence, and the view says
  so.

- **A failing flow now says what to do about it**, in two visibly separate
  halves because they are worth different amounts. The **Measured** half is
  computed from the artefacts: how many other flows closed with the same reason
  within a minute, and across how many destinations. On the session in hand the
  `next_transport_state` flow the reader asked about turned out to be one of
  **6 flows closing that way inside a minute across 5 different destinations** -
  which points at the tunnel underneath rather than at the destination, and is
  a conclusion no single flow could support. The **Possible causes** half is
  general knowledge about the reason code and is labelled *"general guidance,
  not a finding from your files"* - it is the only text in the tool not derived
  from the inputs, and saying so is what keeps the rest trustworthy. Covers
  `next_transport_state`, `socket_read`, `socket_write`, `connect_timeout`,
  `tunnel_connect` and `connect_transport`.

- **Hoverable "i" explanations on the vocabulary.** The flow table borrows
  words from three places - the agent's own tokens, Wireshark's, and this
  tool's joins - and a reader cannot act on a word they have to guess at.
  Twelve terms (severity, SNI, listener, stream, handshake, HAR and the rest)
  now carry a small hoverable icon. The severity one states the actual rule:
  High means the agent closed the flow on an error reason or its requests
  failed.

- **An end-to-end path view.** Captures taken at several points of a path -
  client, Zproxy egress, FTD, resource - are stitched into one chain, and the
  order of the hops is inferred rather than asked for: where a proxy joins two
  legs, its own address appears as a destination in one capture and a source in
  the next, and that pivot orders the chain. The view separates two kinds of
  hop, because only one of them can be proved. A forwarding device passes the
  TCP sequence number through untouched, so the same connection seen from two
  vantage points carries the same ISN *even across NAT* - an exact join. A
  proxy terminates the connection and opens its own, so nothing is shared and
  the link is reported as inference, with the wording saying that another
  request for the same name in the same second would look identical.
  New: `packages/atlas_core/atlas_core/path.py`, `POST /atlas/api/path`, and an
  "End-to-end path" rail view. `extract_wire_flows` now also reads
  `tcp.seq_raw`, which is what makes the exact join possible.

  Verified against captures constructed for the purpose, not collected: a
  three-vantage ZTA chain (client -> Zproxy -> CNHE, with the FTD seeing the
  second leg NAT'd to a different address and port) produced one transaction,
  named after the resource rather than the proxy, with the NAT'd leg correctly
  recognised as one connection seen at two vantage points. Four tests cover the
  NAT join, the refusal to call a proxied hop proved, the refusal to stitch two
  unrelated captures together, and the note emitted when a capture holds no
  handshake. **No real multi-hop capture was available**, so nothing here has
  been tested against a real Zproxy, FWaaS, ASAc or FTD; device logs are not
  read at all yet.

- **Each flow says what handled it**, in a fixed order of precedence: ZTA, then
  RA VPN, then Umbrella, then local breakout. The order matters because the
  tests overlap - a flow inside a VPN tunnel still has a real destination, and
  an Umbrella-steered flow still leaves the machine normally - so the most
  specific evidence is taken first. ZTA is direct evidence (the bundle names
  the flow, or it went to the listener the bundle accounts for); Umbrella and
  Secure Access are named addresses; a VPN is reported as *consistent with*
  rather than proven, because a capture cannot read an adapter's name. Measured
  on the YouTube session: 382 ZTA, 3 local breakout, `accounts.youtube.com`
  correctly identified as going straight to 142.251.218.142 from the machine's
  own address.
- **A real packet ladder for every correlated flow the capture holds.** An
  intercepted flow has a real client and a real server - the application on one
  side, the destination it asked for on the other - so it has a real packet
  ladder. The previous entry claimed otherwise; that was wrong, and the reason
  was a limitation of this code rather than of the data:
  `extract_wire_flows` kept only per-flow aggregates and discarded the packets.
  It now keeps the opening and closing packets of each connection, and the
  ladder is drawn from them: SYN, SYN/ACK, ACK, `Data 1211B`, FIN, RST, each on
  the side that sent it. Where the capture does **not** hold the connection
  there are still no packets, and the agent's log lines are shown instead,
  labelled as its account rather than as traffic. Verified: 14-packet ladder
  for `crl.prod.cagenerator.pki.strln.net`, lifelines `127.0.0.1:59897` and the
  destination "via 127.0.0.1:52555", directions alternating correctly.
- **A flow timeline for each correlated flow**, drawn as the capture engine
  draws a connection: a two-column fact grid, the artefact chain, then a ladder
  between two lifelines. The rows are the agent's own log lines **in order, not
  packets** - the correlation never reads individual packets - so the lifelines
  are the leg facing the application and the leg facing Secure Access, taken
  from the subsystem the agent named on each line. The diagram says that on
  screen rather than letting a familiar shape imply a packet capture. Verified:
  four ordered lines with alternating sides, endpoints "application · port
  59682" and the tunnel, error rows marked.
- **A Remove control on every evidence tile.** There was no way to take a file
  back once chosen, which is what made a browser-restored selection feel like
  the tool inventing data: the file was genuinely still attached and could not
  be detached. Verified: removing the capture clears its input and label and
  leaves the bundle untouched.
- **A running analysis now says it is still running.** The notice was written
  once - "This can take a minute" - and then never changed, so a two-to-three
  minute concurrent run was indistinguishable from a hang. It has been reported
  as one three times. The notice now names what is in flight and ticks an
  elapsed time. That is not progress and does not claim to be; it shows the run
  is alive. Verified: 0:02 through 0:24 on a bundle-only run, cleared when the
  results rendered.
- **Flow-level correlation across a DART bundle, a packet capture and a HAR**
  (`packages/atlas_core/atlas_core/flows.py`, `POST /atlas/api/correlate`).
  Joins the three artefacts into one session view: which hostnames were steered
  and which went direct, which tunnels carried them, and what the agent reported
  about each. Two join strengths are carried through to the UI so an association
  is never read as a measurement. Measured on a real three-artefact session: 19
  hosts, 18 steered, 1 direct, 5 tunnels matched, 162 requests, 9 failures.
- **Intercepted flows, end to end.** The ZTA log writes two differently
  punctuated flow identifiers and only one was being read. The host-named form,
  `tcp:50299__enroll.cisco.com stream=1`, names the destination the application
  asked for - the only place any artefact states both a recognisable destination
  and the source port that leads into the capture. All 2,180 lines of that form
  were previously invisible. Each flow is now followed HAR host -> source port ->
  captured connection -> HTTP/2 stream -> tunnel -> close reason, with every hop
  labelled by the artefact it came from. Measured: 340 flows named, 269 tied to a
  tunnel, and the two inside the capture window tied exactly.
- **One report for the whole workspace.** The Report view and both existing
  export buttons now emit a single report covering the capture, the bundle and
  the correlation, opening with the filenames of every artefact it was made from.
  Measured: 641,914 characters against the previous 293.
- **Correlation runs from Analyze** whenever two or more artefacts are loaded,
  rather than requiring a second click in another view.
- **tshark field capability probe** (`capture_inspector.pcap.supported_fields`).
  Unknown fields are dropped and named in a note instead of failing the run.

### Changed

- **Flows the capture holds are listed first.** Those are the ones that can be
  shown packet by packet, which is the strongest evidence this tool produces.
  Within each group the worst still come first, so the ordering reads "what can
  be proven, then what went wrong" rather than one at the expense of the other.
  Verified: the two capture-matched flows lead the table, followed by the
  problem flows the capture does not hold.
- **Correlated flows are presented as a flow table**, the way the capture engine
  presents its own: same columns, same severity pills, same expand-for-detail,
  same "Show only problems" and filter - and reusing that engine's classes
  rather than inventing a second style for the same idea. A reader who has
  learned one table has learned both. The chain, the join bases and the agent's
  own error lines moved into the expanded row. Verified on a capture plus
  bundle: 340 flows, 200 rows shown worst-first, filtering to "msn" leaves 15,
  the expanded row carries all four hops, and the engine's styling applies
  natively.
- **A reload now starts over.** Firefox restores file input selections across a
  reload, the way it restores text typed into a field; Chromium does not, which
  is why the browser harness could not see it. The result was a half-state - the
  files survived but their results did not - so an apparently empty page would
  analyse artefacts the reader believed they had never supplied. Showing the
  restored files rather than hiding them was the first attempt and was not
  enough: reported three times. Selections are now dropped at startup. Nothing
  is lost that a reload was not already discarding, and Remove takes a file back
  without one. Verified: two files loaded, reload leaves zero and both tiles
  read "no file selected".
- **Analyze no longer moves the view** when doing so would hide a result the same
  click produced - but it does land on the bundle results when the bundle is the
  only artefact supplied, because there is then nothing to hide.
- **The Analyze notice names the artefacts** instead of counting them. A file
  input keeps its selection until the page reloads, so "3 artefacts" could be
  true while the user believed they had supplied one.
- **Correlation refuses ambiguous joins rather than guessing.** Two captured
  flows claiming one source port produce no join and a counted note. The
  app-flow to tunnel join is bounded to one second, which cut ambiguous cases
  from 163 to 23.

### Fixed

- **Flows that worked were missing entirely.** The flow list was keyed on the
  ZTA log, and with trace-level logging off the agent names a destination only
  when something goes wrong - so a capture full of loopback connections carrying
  a hostname, and a HAR full of requests to it, produced no flow at all. A flow
  now exists if **any** artefact names it, and each row records which one did.
  Measured on the BBC pair: 2 packet ladders before, **62** after, out of 397
  flows. A flow named by the capture alone does not claim the agent intercepted
  it - no artefact says that - it states what the capture holds and that the
  agent's log is silent.
- **Exporting from the Bundle analysis page produced an almost empty report.**
  `innerText` returns only what is *rendered*, and the bundle output sits almost
  entirely inside a collapsed `<details>` ("All checks and full output"), so the
  export was 1,695 characters. The 387,719 measured earlier was itself
  misleading: that read happened while the block was in a hidden subtree, where
  `innerText` falls back to `textContent` and quietly returns everything. The
  reader now opens collapsed sections, reads them, and restores them exactly as
  they were. Verified from the Bundle analysis page: 1,695 to 387,331
  characters, containing the evidence header, the bundle section and the
  individual checks, with all nine `<details>` still closed afterwards.
- **A new run showed the previous run's results.** Nothing was cleared when
  Analyze started, so analysing a bundle after a capture left the capture's
  findings, its correlation and its notice on screen - output describing
  artefacts the current run never touched. Reported as "not sure how it is
  showing this data". Everything a run will not produce is now removed before
  it starts. Verified: 200 flow rows from a capture disappear the moment a
  bundle-only run begins, and the report then contains only the bundle.
- **Filename labels could disagree with the files actually loaded.** Each label
  is written by a `change` or `drop` handler and by nothing else, so it
  describes the last interaction rather than the state of the input. Browsers
  restore file input selections across a reload, which leaves a capture in the
  input while the tile reads "no file selected" - and a correlation honestly
  reporting "capture + bundle + har" beside two tiles claiming nothing was
  chosen. The labels are now synced from the inputs at startup; the files are
  real and are not discarded. **Not verified against the browser that restores
  them:** Chromium, which the test harness drives, does not restore file
  inputs, so only the divergence this produces was reproduced, not the restore
  itself.
- **The Report view was unreachable without a capture.** Two causes, both
  found by measurement. The engine treats its views as scroll targets on one
  long page and its Report handler returns the reader to the evidence card
  unless *it* has analysed a capture; and the shell's report block was being
  rendered inside `#sec-report`, which sits inside `#results`, which the engine
  keeps hidden until then - so it was present with 387,541 characters of
  content and zero height. The block now lives outside that subtree, carries
  its own Download button when there is no capture, and the shell takes over
  the Report click only when the engine would have refused. Verified: bundle
  alone now scrolls to a rendered report (scrollY 1739, section on screen,
  387,719 characters exported); with a capture the engine's own handler still
  runs and targets `sec-report`, unchanged.
- **Every capture failed on Wireshark below 3.6.** `tls.handshake.ja3` and
  `ja3s` arrived in 3.6; tshark rejects the entire run if any one `-e` field is
  unknown, so the 3.4.7 build in use returned "Some fields aren't valid" for
  every capture. Verified after the fix: 14,491 packets parsed, exactly the two
  fields dropped and 83 kept, 63 findings, HTTP 200 in 6.2 s.
- **A HAR-only analysis listed nothing but failures.** `_har_rows` sent only
  `har.failed`, so a 158-entry HAR arrived as 19 rows, all errors, while the
  table offered a "Show only problems" control with nothing to filter. Now 19
  problems and 81 successes on the first page, 19 when ticked.
- **The capture engine's assets were never cache-busted.** The markup carried a
  hand-written `?v=20260651` that does not change when the file does, so
  browsers served a stale `app.js` after every edit. Both emitters now stamp
  with the file's modification time.
- **The bundle engine raised "Please select one ZTA analysis check option"** on
  a workflow that deliberately never asks that question. The guard used
  `offsetParent` to test visibility, which is `null` for everything inside the
  hidden engine regardless of what the engine intends.
- **A bundle-only analysis appeared to do nothing.** It rendered 387,299
  characters into a panel the reader was not looking at, then cleared its own
  notice.

### Documentation

- `docs/STATE.md` records the correlation join keys, the two deliberate
  refusals, and seven traps paid for during this work.
- This changelog added, along with the rule in [`AGENTS.md`](AGENTS.md) that
  requires it to be updated in the same change.
- `docs/IMPROVEMENTS.md` added: a standing, evidence-backed list of what should
  be improved next.

---

## Earlier work

Before this file existed, history was kept only in `docs/STATE.md` and in commit
messages, both of which remain accurate. Notable earlier changes, newest first:

- `452ca7e` Show one bundle view at a time, with a way back to the summary.
- `9b6033f` Let the ZTA Health Snapshot be the verdict, fold the checks beneath it.
- `b9d37e5` Group run-everything results by the question each check asks.
