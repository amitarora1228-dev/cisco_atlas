(function () {
    function parseFlowCandidatesFromOutput(detailsText) {
        const lines = String(detailsText || '').split(String.fromCharCode(10));
        const candidates = [];
        let current = null;

        for (const rawLine of lines) {
            const line = rawLine.trim();

            if (line.startsWith('- Match #')) {
                if (current && current.srcPort) {
                    candidates.push(current);
                }
                current = {
                    match: line.replace('- Match #', '').trim(),
                    time: '',
                    destination: '',
                    realDestinationIp: '',
                    srcPort: '',
                    process: '',
                    ruleType: '',
                };
                continue;
            }

            if (!current) {
                continue;
            }

            if (line.startsWith('Time: ')) {
                current.time = line.replace('Time: ', '').trim();
            } else if (line.startsWith('TCP/UDP Destination:Port: ')) {
                current.destination = line.replace('TCP/UDP Destination:Port: ', '').trim();
            } else if (line.startsWith('Real Destination IP: ')) {
                current.realDestinationIp = line.replace('Real Destination IP: ', '').trim();
            } else if (line.startsWith('Source Port: ')) {
                current.srcPort = line.replace('Source Port: ', '').trim();
            } else if (line.startsWith('Process: ')) {
                current.process = line.replace('Process: ', '').trim();
            } else if (line.startsWith('Match Rule Type: ')) {
                current.ruleType = line.replace('Match Rule Type: ', '').trim();
            }
        }

        if (current && current.srcPort) {
            candidates.push(current);
        }

        return candidates;
    }

    function parseSortableTime(value) {
        const time = Date.parse(value || '');
        return Number.isNaN(time) ? null : time;
    }

    function buildFlowVisualizerData(candidates) {
        const destinations = new Map();
        const uniqueSrcPorts = new Set();

        candidates.forEach((candidate) => {
            const destinationKey = candidate.destination || 'Unknown destination';
            if (!destinations.has(destinationKey)) {
                destinations.set(destinationKey, {
                    destination: destinationKey,
                    realDestinationIp: candidate.realDestinationIp || '',
                    totalMatches: 0,
                    sessions: new Map(),
                });
            }

            const destinationGroup = destinations.get(destinationKey);
            destinationGroup.totalMatches += 1;
            if (!destinationGroup.realDestinationIp && candidate.realDestinationIp) {
                destinationGroup.realDestinationIp = candidate.realDestinationIp;
            }

            const srcPortKey = candidate.srcPort || 'Unknown';
            uniqueSrcPorts.add(srcPortKey);

            if (!destinationGroup.sessions.has(srcPortKey)) {
                destinationGroup.sessions.set(srcPortKey, {
                    srcPort: srcPortKey,
                    count: 0,
                    firstTime: candidate.time || '',
                    lastTime: candidate.time || '',
                    process: candidate.process || 'Unknown process',
                    ruleType: candidate.ruleType || 'Unknown',
                    entries: [],
                });
            }

            const session = destinationGroup.sessions.get(srcPortKey);
            session.count += 1;
            session.entries.push(candidate);

            const currentTime = parseSortableTime(candidate.time);
            const firstTime = parseSortableTime(session.firstTime);
            const lastTime = parseSortableTime(session.lastTime);

            if (currentTime !== null) {
                if (firstTime === null || currentTime < firstTime) {
                    session.firstTime = candidate.time;
                }
                if (lastTime === null || currentTime > lastTime) {
                    session.lastTime = candidate.time;
                }
            }
        });

        const destinationRows = Array.from(destinations.values()).map((destination) => {
            const sessions = Array.from(destination.sessions.values()).sort((a, b) => {
                const aTime = parseSortableTime(a.firstTime || a.lastTime || '');
                const bTime = parseSortableTime(b.firstTime || b.lastTime || '');

                if (aTime !== null && bTime !== null && aTime !== bTime) {
                    return aTime - bTime;
                }
                if (aTime !== null && bTime === null) {
                    return -1;
                }
                if (aTime === null && bTime !== null) {
                    return 1;
                }
                return (a.srcPort || '').localeCompare(b.srcPort || '');
            });
            return {
                destination: destination.destination,
                realDestinationIp: destination.realDestinationIp,
                totalMatches: destination.totalMatches,
                sessionCount: sessions.length,
                sessions,
            };
        }).sort((a, b) => b.totalMatches - a.totalMatches);

        return {
            totalMatches: candidates.length,
            destinationCount: destinationRows.length,
            sourcePortCount: uniqueSrcPorts.size,
            destinationRows,
        };
    }

    function parseSelectedFlowTraceFromOutput(detailsText) {
        const lines = String(detailsText || '').split(String.fromCharCode(10));
        const tracesByPort = {};
        let activePort = '';
        let inTraceBlock = false;

        lines.forEach((rawLine) => {
            const line = rawLine || '';
            const trimmed = line.trim();

            const traceHeaderMatch = trimmed.match(/^\[Selected Flow Trace: srcPort=(.+)\]$/);
            if (traceHeaderMatch) {
                activePort = traceHeaderMatch[1].trim();
                tracesByPort[activePort] = [];
                inTraceBlock = true;
                return;
            }

            const isSectionHeader = /^\[[A-Za-z][^\]]*\]$/.test(trimmed);
            const isDnsQuestionLine = /^\[q:\s*/i.test(trimmed);
            if (inTraceBlock && isSectionHeader && !isDnsQuestionLine && !trimmed.startsWith('[Selected Flow Trace:')) {
                inTraceBlock = false;
                activePort = '';
                return;
            }

            if (!inTraceBlock || !activePort) {
                return;
            }

            if (trimmed.startsWith('- Matched Lines:') || line.startsWith('  - ') || line.startsWith('    ')) {
                tracesByPort[activePort].push(line);
            }
        });

        return tracesByPort;
    }

    function cleanTraceLinesForDownload(traceLines) {
        return (traceLines || [])
            .map((line) => String(line || ''))
            .filter((line) => line.startsWith('    '))
            .map((line) => line.trim())
            .filter((line) => !/^Questions\s*\(\d+\)$/i.test(line));
    }

    function cleanTraceLinesForDisplay(traceLines) {
        return (traceLines || [])
            .map((line) => String(line || ''))
            .filter((line) => {
                const trimmed = line.trim();
                if (!trimmed) {
                    return false;
                }
                if (trimmed.startsWith('- Matched Lines:')) {
                    return false;
                }
                if (/^-\s+.+:L\d+$/i.test(trimmed)) {
                    return false;
                }
                return line.startsWith('    ');
            })
            .map((line) => line.trimEnd());
    }

    function classifyTraceDirection(text) {
        const lower = String(text || '').toLowerCase();
        if (/(established|connected|response|received|recv|serverhello|reply|handshake (?:complete|done)|200 ok|closed by peer|teardown|from server|inbound)/.test(lower)) {
            return 'in';
        }
        if (/(redirected flow|createappsockettransport|buildstack|appsockettransport created|connect|sending|send |request|clienthello|tls|syn|tunnel|proxyconfig|outbound|forward)/.test(lower)) {
            return 'out';
        }
        return 'self';
    }

    function humanizeCamelCase(value) {
        return String(value || '')
            .replace(/_/g, ' ')
            .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
            .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
            .replace(/\s+/g, ' ')
            .trim();
    }

    function deriveActionLabel(line) {
        const classMatch = String(line || '').match(/([A-Za-z][A-Za-z0-9_]+)::([A-Za-z0-9_~]+)\s*\(/);
        if (classMatch) {
            const className = classMatch[1];
            const methodName = classMatch[2].replace(/^~/, '');
            return humanizeCamelCase(methodName === className ? className : methodName);
        }
        const fileMatch = String(line || '').match(/([A-Za-z][A-Za-z0-9_]+)\.(?:cpp|cc|hpp|h|c):\d+/);
        if (fileMatch) {
            return humanizeCamelCase(fileMatch[1]);
        }
        return '';
    }

    function detectAccessType(displayTraceLines) {
        const lines = (displayTraceLines || []).map((line) => String(line || ''));
        for (let i = 0; i < lines.length; i += 1) {
            const match = lines[i].match(/matched ProxyConfig:\s*(Secure (?:Private|Internet) Access)/i);
            if (match) {
                return match[1].replace(/\bprivate\b/i, 'Private').replace(/\binternet\b/i, 'Internet');
            }
        }
        for (let i = 0; i < lines.length; i += 1) {
            if (/secure private access/i.test(lines[i])) {
                return 'Secure Private Access';
            }
            if (/secure internet access/i.test(lines[i])) {
                return 'Secure Internet Access';
            }
        }
        return '';
    }

    function normalizeAccessName(value) {
        return String(value || '')
            .replace(/secure/i, 'Secure')
            .replace(/private/i, 'Private')
            .replace(/internet/i, 'Internet')
            .replace(/access/i, 'Access');
    }

    // Recognizes the meaningful Cisco Secure Access ZTA flow steps and maps each
    // to a clean label + lane direction. Returns null for lines we don't surface.
    // direction: 'out' = ZTA Client -> ZProxy, 'in' = ZProxy -> ZTA Client,
    //            'self' = client-side processing, 'both' = bidirectional app data.
    // kind: 'step' (normal), 'tunnelComplete' (starts application-data phase),
    //       'terminal' (tunnel disconnect / close / error ends the flow).
    function deriveFlowEvent(rawLine) {
        const line = String(rawLine || '');
        const lower = line.toLowerCase();

        // Terminal / teardown events that end the application-data phase.
        if (/handleClose\s*\(\)/.test(line)) {
            if (/disconnecting tunnel/i.test(line)) {
                return { label: 'Handle Close \u2014 Disconnecting tunnel', direction: 'out', kind: 'terminal' };
            }
            const reasonMatch = line.match(/closing due to reason:\s*(.+?)(?:\s+state=|$)/i);
            let reason = reasonMatch ? reasonMatch[1].trim() : 'Connection closed';
            if (/forcibly closed by the remote host/i.test(reason)) {
                reason = 'Connection closed by remote host';
            } else if (/reset by (?:the )?(?:remote )?peer|connection reset/i.test(reason)) {
                reason = 'Connection reset by peer';
            } else if (/timed? ?out/i.test(reason)) {
                reason = 'Connection timed out';
            } else {
                reason = reason.replace(/\s*\.\s*$/, '');
            }
            return { label: 'Handle Close \u2014 ' + reason, direction: 'in', kind: 'terminal' };
        }
        if (/handletunneldisconnect|tunnel disconnect|disconnected/.test(lower)) {
            return { label: 'Tunnel Disconnected', direction: 'in', kind: 'terminal' };
        }
        if (/closed by peer|connection closed|teardown/.test(lower)) {
            return { label: 'Connection Closed', direction: 'in', kind: 'terminal' };
        }
        if (/tunnel.*error|connect.*error|reset by peer|connection reset/.test(lower)) {
            return { label: 'Error', direction: 'in', kind: 'terminal' };
        }

        // Graceful half-close teardown: ZProxy signals end-of-stream downstream.
        if (/pullRecvDataFromNextTransport[^\n]*eof received from downstream/i.test(line)) {
            return { label: 'Connection EOF \u2014 received from Z Proxy', direction: 'in', kind: 'terminal' };
        }
        // Draining completes with no remaining data -> connection closes.
        if (/checkDrainingState[^\n]*proceeding with close/i.test(line)) {
            return { label: 'Connection Closed \u2014 draining complete', direction: 'in', kind: 'terminal' };
        }

        // 8. Tunnel connect complete -> start of application-data phase.
        if (/handleTunnelConnectComplete\s*\(\)/.test(line)) {
            return { label: 'Tunnel Connect Complete \u2014 Connected', direction: 'in', kind: 'tunnelComplete' };
        }

        // 1 & 2. CreateAppSocketTransport (client-side matching / stack spec).
        if (/CreateAppSocketTransport\s*\(\)/.test(line)) {
            const proxyMatch = line.match(/matched ProxyConfig:\s*(Secure (?:Private|Internet) Access)/i);
            if (proxyMatch) {
                return {
                    label: 'Create App Socket Transport \u2014 matched ProxyConfig: ' + normalizeAccessName(proxyMatch[1]),
                    direction: 'self',
                    kind: 'step',
                };
            }
            const specMatch = line.match(/ProtocolStackSpec:\s*([A-Za-z0-9 ]+?)(?:\s+transportMeta|\s+for\b|\s*$)/);
            if (specMatch) {
                return {
                    label: 'Create App Socket Transport \u2014 ProtocolStackSpec: ' + specMatch[1].trim(),
                    direction: 'self',
                    kind: 'step',
                };
            }
            return { label: 'Create App Socket Transport', direction: 'self', kind: 'step' };
        }

        // 3. buildStackFromSpec (client-side, include ProtocolStackSpec).
        if (/buildStackFromSpec\s*\(\)/.test(line)) {
            const specMatch = line.match(/ProtocolStackSpec:\s*([A-Za-z0-9 ]+?)(?:\s+transportMeta|\s*$)/);
            const spec = specMatch ? specMatch[1].trim() : '';
            return {
                label: 'Build Stack From Spec' + (spec ? ' \u2014 ProtocolStackSpec: ' + spec : ''),
                direction: 'self',
                kind: 'step',
            };
        }

        // 4. AppSocketTransport created -> client reaches out to ZProxy.
        if (/AppSocketTransport\b[^\n]*\bcreated\b/i.test(line)) {
            return { label: 'App Socket Transport Created', direction: 'out', kind: 'step' };
        }

        // NetworkTransportStateTracker transitions (e.g. Initialized->Connecting).
        const netMatch = line.match(/NetworkTransportStateTracker::transitionState\s*\(\)[^\n]*transitoned state:\s*([A-Za-z]+->[A-Za-z]+)/);
        if (netMatch) {
            const netTrans = netMatch[1];
            // State transitions into draining/closing/half-closed mark teardown,
            // so they survive the application-data collapse and are surfaced.
            const isTeardown = /->\s*(?:Draining|Closing|Closed|HalfClosed[A-Za-z]*)$/i.test(netTrans);
            return {
                label: 'Network Transport State \u2014 ' + netTrans,
                direction: /->\s*Connected$/i.test(netTrans) ? 'in' : 'out',
                kind: isTeardown ? 'terminal' : 'step',
            };
        }

        // ProxyConnectStateTracker transitions (e.g. Unknown->Contacting).
        const proxyStateMatch = line.match(/ProxyConnectStateTracker::transitionState\s*\(\)[^\n]*proxy_connect_state:\s*([A-Za-z]+->[A-Za-z]+)/);
        if (proxyStateMatch) {
            const proxyTrans = proxyStateMatch[1];
            return {
                label: 'Proxy Connect State \u2014 ' + proxyTrans,
                direction: /->\s*Connected$/i.test(proxyTrans) ? 'in' : 'out',
                kind: 'step',
            };
        }

        // AppSocketTransport next transport state change (e.g. Connected).
        const nextStateMatch = line.match(/OnNextTransportStateChange\s*\(\)[^\n]*nextTransportState:\s*([A-Za-z]+)/);
        if (nextStateMatch) {
            const nextState = nextStateMatch[1];
            return {
                label: 'App Socket Transport \u2014 nextTransportState: ' + nextState,
                direction: /connected/i.test(nextState) ? 'in' : 'out',
                kind: 'step',
            };
        }

        return null;
    }

    function summarizeAppDataLines(rawLines, firstTimestamp, lastTimestamp) {
        const count = rawLines.length;
        const header = 'Application data phase \u2014 ' + count + ' log line' + (count === 1 ? '' : 's')
            + (firstTimestamp ? '\nFrom: ' + firstTimestamp : '')
            + (lastTimestamp ? '\nTo:   ' + lastTimestamp : '');
        if (!count) {
            return header + '\n\n(No intermediate log lines were captured for the application-data phase. '
                + 'This phase represents encrypted bidirectional traffic between the ZTA Client and Z Proxy.)';
        }
        const cap = 40;
        let preview;
        if (count <= cap * 2) {
            preview = rawLines.join('\n');
        } else {
            preview = rawLines.slice(0, cap).join('\n')
                + '\n\n  ... ' + (count - cap * 2) + ' more lines ...\n\n'
                + rawLines.slice(count - cap).join('\n');
        }
        return header + '\n\n' + preview;
    }

    function buildFlowSequenceModel(session, destinationRow, displayTraceLines) {
        session = session || {};
        destinationRow = destinationRow || {};
        const lines = (displayTraceLines || []).map((line) => String(line || ''));
        const events = [];
        let appDataStarted = false;
        let appDataEvent = null;
        let appDataLines = [];
        let appDataFirstTs = '';
        let appDataLastTs = '';

        const finalizeAppData = () => {
            if (appDataEvent) {
                appDataEvent.raw = summarizeAppDataLines(appDataLines, appDataFirstTs, appDataLastTs);
            }
            appDataEvent = null;
            appDataLines = [];
            appDataFirstTs = '';
            appDataLastTs = '';
        };

        lines.forEach((rawLine, lineIdx) => {
            const line = rawLine.trim();
            if (!line) {
                return;
            }
            const ev = deriveFlowEvent(line);
            const tsMatch = line.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)/);
            const timestamp = tsMatch ? tsMatch[1] : '';

            if (appDataStarted) {
                // Collapse everything after tunnel-connect-complete into a single
                // "Application Data" row until the flow tears down. A terminal
                // event ends the phase; all other lines are captured so the
                // Application Data row can show its underlying raw log lines.
                if (ev && ev.kind === 'terminal') {
                    finalizeAppData();
                    events.push({ timestamp: timestamp, label: ev.label, direction: ev.direction, raw: line, logIndex: lineIdx });
                    appDataStarted = false;
                    return;
                }
                appDataLines.push(line);
                if (timestamp) {
                    if (!appDataFirstTs) {
                        appDataFirstTs = timestamp;
                    }
                    appDataLastTs = timestamp;
                }
                return;
            }

            if (!ev) {
                return;
            }

            events.push({ timestamp: timestamp, label: ev.label, direction: ev.direction, raw: line, logIndex: lineIdx });

            if (ev.kind === 'tunnelComplete') {
                appDataStarted = true;
                appDataEvent = { timestamp: timestamp, label: 'Application Data', direction: 'both', raw: '', logIndex: lineIdx };
                events.push(appDataEvent);
            }
        });

        // Flow ended while still in the application-data phase (no teardown line).
        finalizeAppData();

        // Fallback: generic parsing when no specific ZTA proxy steps were found.
        if (!events.length) {
            lines.forEach((rawLine, lineIdx) => {
                const line = rawLine.trim();
                if (!line) {
                    return;
                }
                const label = deriveActionLabel(line);
                if (!label) {
                    return;
                }
                const tsMatch = line.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)/);
                events.push({
                    timestamp: tsMatch ? tsMatch[1] : '',
                    label: label,
                    direction: classifyTraceDirection(line),
                    raw: line,
                    logIndex: lineIdx,
                });
            });
        }

        if (!events.length && Array.isArray(session.entries)) {
            session.entries.forEach((entry) => {
                events.push({
                    timestamp: (entry && entry.time) || '',
                    label: 'Redirected Flow',
                    direction: 'out',
                    raw: (entry && entry.raw) || '',
                });
            });
        }

        return {
            clientLabel: 'ZTA Client',
            proxyLabel: 'Z Proxy',
            accessType: detectAccessType(displayTraceLines),
            process: session.process || 'Unknown process',
            srcPort: session.srcPort || '?',
            destination: destinationRow.destination || '',
            realDestinationIp: destinationRow.realDestinationIp || '',
            ruleType: session.ruleType || 'Unknown',
            firstTime: session.firstTime || '',
            lastTime: session.lastTime || '',
            eventCount: events.length,
            events: events,
            logLines: lines,
        };
    }

    function titleCasePhrase(phrase) {
        return String(phrase || '')
            .trim()
            .replace(/\s+/g, ' ')
            .replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }

    function humanizeAcmePath(path) {
        const p = String(path || '').toLowerCase();
        if (/\/directory/.test(p)) return 'ACME Get Directory';
        if (/new-nonce/.test(p)) return 'ACME Get Nonce';
        if (/new-account/.test(p)) return 'ACME Create Account';
        if (/new-order/.test(p)) return 'ACME Submit Order';
        if (/finalize/.test(p)) return 'ACME Finalize Order';
        if (/\/certificate\//.test(p)) return 'ACME Get Certificate';
        if (/\/authz\//.test(p) || /challenge/.test(p)) return 'ACME Authorization / Challenge';
        if (/\/order\//.test(p)) return 'ACME Order Status';
        return 'ACME Request';
    }

    // Map a single ZTA enrollment trace line to a sequence-diagram event.
    // direction: out  = ZTA Client -> Cisco Secure Access (request sent),
    //            in   = Cisco Secure Access -> ZTA Client (response received),
    //            self = client-side processing, both = user interaction.
    function deriveEnrollmentFlowEvent(rawLine) {
        const line = String(rawLine || '');

        // Inbound HTTP responses: "received <phrase> response with http_status:NNN".
        const respMatch = line.match(/received\s+(.+?)\s+response\s+with\s+http_status:\s*(\d+)/i);
        if (respMatch) {
            const status = parseInt(respMatch[2], 10);
            return {
                label: titleCasePhrase(respMatch[1]) + ' Response \u2014 HTTP ' + respMatch[2],
                direction: 'in',
                kind: 'step',
                error: status >= 400,
            };
        }

        // Enrollment lifecycle triggers.
        if (/Handling InitiateEnrollment from client/i.test(line)) {
            return { label: 'Initiate Enrollment', direction: 'self', kind: 'start' };
        }
        if (/initiating unenrollment/i.test(line)) {
            return { label: 'Unenrollment Triggered', direction: 'self', kind: 'step' };
        }
        if (/initiating (?:automatic )?enrollment/i.test(line)) {
            return { label: 'Auto-Enrollment Triggered', direction: 'self', kind: 'step' };
        }

        // Bootstrap request.
        if (/actionSendBootstrapRequest/i.test(line)) {
            if (/Using client certificate/i.test(line)) {
                return { label: 'Bootstrap Request \u2014 using client certificate', direction: 'out', kind: 'step' };
            }
            return { label: 'Bootstrap Request', direction: 'out', kind: 'step' };
        }

        // SAML user authentication (browser based; the user pause).
        if (/eventUserAuthResponse/i.test(line)) {
            return { label: 'SAML User Authentication', direction: 'both', kind: 'step' };
        }
        if (/actionSendUserAuth|user auth request|launching.*browser|external browser/i.test(line)) {
            return { label: 'SAML User Authentication \u2014 awaiting user', direction: 'both', kind: 'step' };
        }

        // ACME certificate issuance requests.
        const acmeMatch = line.match(/AcmeEnroller::SendHttpRequest\(\)\s+Initiated HTTP request\s+method=([A-Z]+)\s+url=https?:\/\/[^/\s]+(\/[^\s]*)/i);
        if (acmeMatch) {
            return { label: humanizeAcmePath(acmeMatch[2]), direction: 'out', kind: 'step' };
        }

        // DHA enrollment milestones.
        if (/actionSendDhaEnrollCommand/i.test(line)) {
            return { label: 'DHA Enrollment Command', direction: 'out', kind: 'step' };
        }
        if (/actionSendDhaEnrollCompleteNotification/i.test(line)) {
            return { label: 'DHA Enrollment Complete Notification', direction: 'out', kind: 'step' };
        }
        if (/Reporting 'successful' enrollment result|issueRequestCallback.*enrollment result/i.test(line)) {
            return { label: 'DHA Enrollment Result \u2014 successful', direction: 'in', kind: 'step' };
        }
        const failResultMatch = line.match(/Reporting '([^']+)' enrollment result/i);
        if (failResultMatch) {
            return { label: 'DHA Enrollment Result \u2014 ' + failResultMatch[1].toLowerCase(), direction: 'in', kind: 'step', error: true };
        }
        if (/DHA enrollment has completed successfully|OnEnrollmentConcluded.*completed successfully/i.test(line)) {
            return { label: 'DHA Enrollment Completed', direction: 'self', kind: 'step' };
        }

        // Config sync.
        if (/sent config sync request/i.test(line)) {
            return { label: 'Config Sync Request', direction: 'out', kind: 'step' };
        }
        if (/received sync response with http_status:\s*(\d+)/i.test(line)) {
            const m = line.match(/http_status:\s*(\d+)/i);
            return { label: 'Config Sync Response \u2014 HTTP ' + (m ? m[1] : ''), direction: 'in', kind: 'step' };
        }

        // Persist enrollment.
        if (/persist(?:ing)? enrollment|actionPersistEnrollment/i.test(line)) {
            return { label: 'Persist Enrollment', direction: 'self', kind: 'step' };
        }

        // Explicit error / failure signals (checked before the generic request
        // fallbacks so a failure surfaces as its own red step in the diagram).
        if (/enrollment (?:failed|error|aborted)|OnEnrollmentFailed|actionHandleError|EnrollmentError|Reporting '(?:fail|error)/i.test(line)) {
            return { label: 'Enrollment Error', direction: 'in', kind: 'step', error: true };
        }

        // Specific enrollment HTTP endpoints (by URL path), checked before the
        // generic request fallback so the milestone names read clearly.
        const urlMatch = line.match(/Initiated HTTP request\s+method=[A-Z]+\s+url=https?:\/\/[^/\s]+(\/[^\s?]*)/i);
        if (urlMatch) {
            const path = urlMatch[1].toLowerCase();
            if (/\/enrollinit$/.test(path)) {
                return { label: 'Bootstrap Request', direction: 'out', kind: 'step' };
            }
            if (/\/deployments\/v2\/ztna|\/ztna$/.test(path)) {
                return { label: 'Device Registration Request', direction: 'out', kind: 'step' };
            }
            if (/dhaenrollinit/.test(path)) {
                return { label: 'DHA Registration Request', direction: 'out', kind: 'step' };
            }
            if (/dhaenrolldone/.test(path)) {
                return { label: 'DHA Enrollment Complete Notification', direction: 'out', kind: 'step' };
            }
        }

        // Generic outbound HTTP request (non-ACME).
        const httpMatch = line.match(/Initiated HTTP request\s+method=([A-Z]+)\s+url=https?:\/\/[^/\s]+(\/[^\s?]*)/i);
        if (httpMatch) {
            const path = httpMatch[2].replace(/\/+$/, '');
            const tail = path.split('/').filter(Boolean).pop() || path;
            return { label: titleCasePhrase(tail.replace(/[-_]+/g, ' ')) + ' Request', direction: 'out', kind: 'step' };
        }

        // Generic actionSend... requests (client -> cloud).
        const actionMatch = line.match(/::actionSend([A-Za-z]+?)\s*\(\)/);
        if (actionMatch) {
            const name = actionMatch[1].replace(/([a-z])([A-Z])/g, '$1 $2');
            return { label: titleCasePhrase(name), direction: 'out', kind: 'step' };
        }

        return null;
    }

    // Build a Visual Flow Analyzer model from the backend enrollment_flow payload.
    function buildEnrollmentFlowModel(payload, attemptIndex) {
        payload = payload || {};
        const attempts = Array.isArray(payload.attempts) ? payload.attempts : [];
        let attempt;
        if (attemptIndex != null) {
            attempt = attempts.find(function (a) { return Number(a.index) === Number(attemptIndex); })
                || attempts[Number(attemptIndex) - 1]
                || { trace_lines: [] };
        } else {
            attempt = attempts.length ? attempts[attempts.length - 1] : { trace_lines: [] };
        }
        const lines = (attempt.trace_lines || []).map(function (l) { return String(l || ''); });
        const events = [];
        let firstTs = '';
        let lastTs = '';

        lines.forEach(function (rawLine, lineIdx) {
            const line = rawLine.trim();
            if (!line) {
                return;
            }
            const ev = deriveEnrollmentFlowEvent(line);
            if (!ev) {
                return;
            }
            const tsMatch = line.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)/);
            const timestamp = tsMatch ? tsMatch[1] : '';
            if (timestamp) {
                if (!firstTs) {
                    firstTs = timestamp;
                }
                lastTs = timestamp;
            }
            // Collapse consecutive duplicate steps (the same milestone is often
            // logged on more than one line) so the diagram stays readable. Two
            // events are treated as duplicates when they share the same direction
            // and the same base label (the text before the " \u2014 " detail).
            const prev = events[events.length - 1];
            const baseLabel = function (text) { return String(text || '').split(' \u2014 ')[0]; };
            if (prev && prev.direction === ev.direction && baseLabel(prev.label) === baseLabel(ev.label)) {
                return;
            }
            const urlMatch = line.match(/url=(\S+)/i);
            const methodMatch = line.match(/method=([A-Z]+)/i);
            events.push({
                timestamp: timestamp,
                label: ev.label,
                direction: ev.direction,
                raw: line,
                url: urlMatch ? urlMatch[1] : '',
                method: methodMatch ? methodMatch[1] : '',
                error: !!ev.error,
                logIndex: lineIdx,
            });
        });

        // Append an explicit terminal milestone when the trace reports the
        // overall enrollment result, so the diagram has a clear end state.
        let overallStatus = '';
        let overallRaw = '';
        let overallIdx = -1;
        for (let i = lines.length - 1; i >= 0; i--) {
            const m = lines[i].match(/Overall result\s*:\s*([A-Za-z]+)/i);
            if (m) {
                overallStatus = m[1].toLowerCase();
                overallRaw = lines[i].trim();
                overallIdx = i;
                break;
            }
        }
        if (overallStatus) {
            const ok = overallStatus === 'success';
            events.push({
                timestamp: lastTs,
                label: ok
                    ? 'Enrollment Completed \u2014 success'
                    : 'Enrollment Ended \u2014 ' + overallStatus,
                direction: 'self',
                raw: overallRaw,
                url: '',
                method: '',
                error: !ok,
                logIndex: overallIdx,
            });
        }

        // Collect the distinct ZTA endpoints the client reached out to, in order,
        // so the diagram can list which URL backs each enrollment step.
        const endpoints = [];
        const seenEndpoint = {};
        events.forEach(function (e) {
            if (!e.url) {
                return;
            }
            const key = (e.method || '') + ' ' + e.url;
            if (seenEndpoint[key]) {
                return;
            }
            seenEndpoint[key] = true;
            endpoints.push({ label: e.label, method: e.method || '', url: e.url });
        });

        const authMethod = payload.auth_method === 'Cert' ? 'Cert' : 'SAML';
        const identifier = attempt.identifier || payload.identifier || '';
        const methodLabel = authMethod === 'Cert' ? 'Cert-based' : 'SAML-based';

        return {
            clientLabel: 'ZTA Client',
            proxyLabel: 'Cisco Secure Access',
            accessType: methodLabel + ' Enrollment',
            process: 'csc_zta_agent',
            srcPort: identifier || 'n/a',
            destination: 'enroll.ztna.sse.cisco.com',
            realDestinationIp: '',
            ruleType: methodLabel + ' Enrollment',
            firstTime: firstTs,
            lastTime: lastTs,
            eventCount: events.length,
            events: events,
            endpoints: endpoints,
            logLines: lines,
            bothLabel: 'User interaction (SAML auth)',
            summaryBits: [
                'Source: ZTA Client (csc_zta_agent)',
                'Enrollment: ' + methodLabel,
                identifier ? 'Enrollment ID: ' + identifier : '',
                'Server: enroll.ztna.sse.cisco.com',
                firstTs ? 'From: ' + firstTs : '',
                lastTs ? 'To: ' + lastTs : '',
                'Events: ' + events.length,
            ].filter(Boolean),
        };
    }

    // Map a single DNS SRV-flow trace line (DnsFlowHandler) to a sequence event.
    // Left actor  = Endpoint (the querying process / ZTA agent interceptor).
    // Right actor = Cisco Secure Access DoH resolver.
    function deriveSrvFlowEvent(rawLine) {
        const line = String(rawLine || '');

        if (/DnsFlowHandler::Start\(\)/.test(line)) {
            return { label: 'DNS Flow Started', direction: 'self', kind: 'start' };
        }
        if (/startDnsRequest\(\)\s+\S+\s+UDP DNS request/i.test(line)) {
            const portMatch = line.match(/flowSrcPort=(\d+)/i);
            return { label: 'DNS SRV Query' + (portMatch ? ' \u2014 srcPort ' + portMatch[1] : ''), direction: 'out', kind: 'step' };
        }
        const ruleMatch = line.match(/matched ProxyConfig:\s*<([^>]+)>\s*bIsDnsRuleMatch=(\w+)/i);
        if (ruleMatch) {
            const matched = /true/i.test(ruleMatch[2]);
            return {
                label: matched
                    ? 'Matched Proxy Config \u2014 ' + ruleMatch[1]
                    : 'No Proxy Config Match \u2014 not steered',
                direction: 'self',
                kind: 'step',
                error: !matched,
            };
        }
        if (/starting doh request/i.test(line)) {
            return { label: 'DoH Request Sent', direction: 'out', kind: 'step' };
        }
        if (/OnDohRequestComplete\(\).*doh request complete/i.test(line)) {
            return { label: 'DoH Request Complete', direction: 'in', kind: 'step' };
        }
        const respMatch = line.match(/Received DNS response.*code=(\w+)/i);
        if (respMatch) {
            const code = respMatch[1].toUpperCase();
            return {
                label: 'DNS Response \u2014 ' + code,
                direction: 'in',
                kind: 'step',
                error: code !== 'DNSNOERROR',
            };
        }
        if (/onRequestComplete\(\).*request complete/i.test(line)) {
            return { label: 'Request Complete', direction: 'self', kind: 'step' };
        }
        const closeMatch = line.match(/handleClose\(\).*closing due to reason:\s*(.+?)\s*$/i);
        if (closeMatch) {
            const reason = closeMatch[1].trim();
            return {
                label: 'Flow Closing \u2014 ' + reason,
                direction: 'self',
                kind: 'step',
                error: !/flow_closed|completed/i.test(reason),
            };
        }
        const statusMatch = line.match(/state=Closed.*closeStatus=(.+?)\s*$/i);
        if (statusMatch) {
            const status = statusMatch[1].trim().replace(/\.$/, '');
            return {
                label: 'Flow Result \u2014 ' + status,
                direction: 'self',
                kind: 'step',
                error: !/completed successfully/i.test(status),
            };
        }
        return null;
    }

    // Build a Visual Flow Analyzer model from a selected SRV-flow trace.
    // payload: { srv, identifier, trace_lines: [string] }
    function buildSrvFlowModel(payload) {
        payload = payload || {};
        const lines = (payload.trace_lines || []).map(function (l) { return String(l || ''); });
        const events = [];
        let firstTs = '';
        let lastTs = '';
        let srcPort = '';
        let resolver = '';
        let processName = '';
        let proxyConfig = '';
        let queryName = String(payload.srv || '');
        let anyError = false;

        lines.forEach(function (rawLine, lineIdx) {
            const line = rawLine.trim();
            if (!line) {
                return;
            }

            // Capture flow metadata from any line (including continuation lines).
            const portMatch = line.match(/flowSrcPort=(\d+)|srcPort=(\d+)/i);
            if (portMatch && !srcPort) { srcPort = portMatch[1] || portMatch[2] || ''; }
            const qMatch = line.match(/\[q:\s*name=(\S+)\s+class=\d+\s+type=\d+\s+SRV\]/i);
            if (qMatch) { queryName = qMatch[1]; }
            const destMatch = line.match(/UDP destination\s+\[([^\]]+)\]:(\d+)/i);
            if (destMatch) { resolver = destMatch[1] + ':' + destMatch[2]; }
            const procMatch = line.match(/process=<([^|>]+)/i);
            if (procMatch && !processName) { processName = procMatch[1].trim(); }
            const cfgMatch = line.match(/matched ProxyConfig:\s*<([^>]+)>/i);
            if (cfgMatch && !proxyConfig) { proxyConfig = cfgMatch[1]; }

            const ev = deriveSrvFlowEvent(line);
            if (!ev) {
                return;
            }
            const tsMatch = line.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)/);
            const timestamp = tsMatch ? tsMatch[1] : '';
            if (timestamp) {
                if (!firstTs) { firstTs = timestamp; }
                lastTs = timestamp;
            }
            if (ev.error) { anyError = true; }

            // Collapse consecutive duplicate steps by base label + direction.
            const prev = events[events.length - 1];
            const baseLabel = function (text) { return String(text || '').split(' \u2014 ')[0]; };
            if (prev && prev.direction === ev.direction && baseLabel(prev.label) === baseLabel(ev.label)) {
                return;
            }
            events.push({
                timestamp: timestamp,
                label: ev.label,
                direction: ev.direction,
                raw: line,
                error: !!ev.error,
                logIndex: lineIdx,
            });
        });

        const endpoints = resolver
            ? [{ label: 'DNS Resolver (DoH)', method: 'UDP', url: resolver }]
            : [];

        return {
            clientLabel: processName || 'Endpoint',
            proxyLabel: 'Secure Access Resolver',
            accessType: proxyConfig || 'DNS SRV Flow',
            process: processName || 'csc_zta_agent',
            srcPort: srcPort || payload.identifier || 'n/a',
            destination: resolver || 'DoH resolver',
            realDestinationIp: '',
            ruleType: 'DNS SRV',
            firstTime: firstTs,
            lastTime: lastTs,
            eventCount: events.length,
            events: events,
            endpoints: endpoints,
            logLines: lines,
            bothLabel: 'Application data',
            summaryBits: [
                'Query: ' + (queryName || 'SRV record'),
                proxyConfig ? 'Proxy Config: ' + proxyConfig : '',
                'Identifier: ' + (payload.identifier || 'n/a'),
                srcPort ? 'Source Port: ' + srcPort : '',
                resolver ? 'Resolver: ' + resolver : '',
                processName ? 'Process: ' + processName : '',
                firstTs ? 'From: ' + firstTs : '',
                lastTs ? 'To: ' + lastTs : '',
                'Events: ' + events.length,
                anyError ? 'Result: error / failure detected' : '',
            ].filter(Boolean),
        };
    }

    function sanitizeFilenamePart(value) {
        return String(value || 'unknown').replace(/[^a-zA-Z0-9._-]+/g, '_');
    }

    function triggerTextDownload(filename, content) {
        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const objectUrl = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = objectUrl;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(objectUrl);
    }

    function buildSessionFallbackLogText(destination, session) {
        const lines = [
            'Flow Match Export',
            `Destination: ${destination}`,
            `Source Port: ${session.srcPort}`,
            `Events: ${session.count}`,
            '',
        ];

        session.entries.forEach((entry, index) => {
            lines.push(`Match #${index + 1}`);
            lines.push(`  Time: ${entry.time || 'Unknown'}`);
            lines.push(`  Destination: ${entry.destination || destination}`);
            if (entry.realDestinationIp) {
                lines.push(`  Real Destination IP: ${entry.realDestinationIp}`);
            }
            lines.push(`  Source Port: ${entry.srcPort || session.srcPort}`);
            lines.push(`  Process: ${entry.process || 'Unknown process'}`);
            lines.push(`  Rule: ${entry.ruleType || 'Unknown'}`);
            lines.push('');
        });

        return lines.join(String.fromCharCode(10));
    }

    window.DarthawkFlowUtils = {
        parseFlowCandidatesFromOutput,
        buildFlowVisualizerData,
        parseSelectedFlowTraceFromOutput,
        cleanTraceLinesForDownload,
        cleanTraceLinesForDisplay,
        buildFlowSequenceModel,
        deriveEnrollmentFlowEvent,
        buildEnrollmentFlowModel,
        deriveSrvFlowEvent,
        buildSrvFlowModel,
        sanitizeFilenamePart,
        triggerTextDownload,
        buildSessionFallbackLogText,
    };
})();
