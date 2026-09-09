const moduleRadios = document.querySelectorAll('input[name="module"]');
        const moduleLabels = document.querySelectorAll('label[for="mod-zta"], label[for="mod-vpn"], label[for="mod-umbrella"], label[for="mod-duo"], label[for="mod-uztna"], label[for="mod-edlp"]');
        const duoOptions = document.getElementById('duoOptions');
        const duoPostureFilterInput = document.getElementById('duoPostureFilterInput');
        const ztaOptions = document.getElementById('ztaOptions');
        const ztaAccessRadios = document.querySelectorAll('input[name="zta_access_mode"]');
        const ztaAccessModeLabels = document.querySelectorAll('label[for="zta-spa"], label[for="zta-sia"]');
        const spaOptions = document.getElementById('spaOptions');
        const spaCheckRadios = document.querySelectorAll('input[name="spa_check_option"]');
        const spaCheckLabels = document.querySelectorAll('label[for^="spa-check-"]');
        const spaEventViewerRadio = document.getElementById('spa-check-event-viewer');
        const spaEventViewerLabel = document.querySelector('label[for="spa-check-event-viewer"]');
        const spaTargetInputWrap = document.getElementById('spaTargetInputWrap');
        const spaTargetInputLabel = document.getElementById('spaTargetInputLabel');
        const spaTargetInput = document.getElementById('spaTargetInput');
        const runTargetInline = document.getElementById('runTargetInline');
        const spaTargetInputHint = document.getElementById('spaTargetInputHint');
        const srvQuickActionWrap = document.getElementById('srvQuickActionWrap');
        const srvCheckOptionRadios = document.querySelectorAll('input[name="srv_check_option"]');
        const srvCheckOptionLabels = document.querySelectorAll('label[for="srv-check-config"], label[for="srv-check-flow"]');
        const srvConfigFilterWrap = document.getElementById('srvConfigFilterWrap');
        const srvConfigFilterInput = document.getElementById('srvConfigFilterInput');
        const srvFlowFilterWrap = document.getElementById('srvFlowFilterWrap');
        const srvFlowFilterInput = document.getElementById('srvFlowFilterInput');
        const srvFlowPresetButtons = document.querySelectorAll('.srv-flow-preset-btn');
        const srvFlowStartTime = document.getElementById('srvFlowStartTime');
        const srvFlowEndTime = document.getElementById('srvFlowEndTime');
        const srvFlowCandidatesWrap = document.getElementById('srvFlowCandidatesWrap');
        const srvFlowCandidatesList = document.getElementById('srvFlowCandidatesList');
        const srvFlowSelectedBadge = document.getElementById('srvFlowSelectedBadge');
        const srvFlowSummary = document.getElementById('srvFlowSummary');
        const spaFlowSourcePortWrap = document.getElementById('spaFlowSourcePortWrap');
        const spaFlowSourcePort = document.getElementById('spaFlowSourcePort');
        const spaFlowFilterWrap = document.getElementById('spaFlowFilterWrap');
        const spaFlowDestinationPort = document.getElementById('spaFlowDestinationPort');
        const spaFlowStartDate = document.getElementById('spaFlowStartDate');
        const spaFlowStartHour = document.getElementById('spaFlowStartHour');
        const spaFlowStartMinute = document.getElementById('spaFlowStartMinute');
        const spaFlowEndDate = document.getElementById('spaFlowEndDate');
        const spaFlowEndHour = document.getElementById('spaFlowEndHour');
        const spaFlowEndMinute = document.getElementById('spaFlowEndMinute');
        const runSpaFlowInline = document.getElementById('runSpaFlowInline');
        const spaFlowCandidatesWrap = document.getElementById('spaFlowCandidatesWrap');
        const spaFlowCandidatesList = document.getElementById('spaFlowCandidatesList');
        const spaFlowSelectedBadge = document.getElementById('spaFlowSelectedBadge');
        const spaFlowSummary = document.getElementById('spaFlowSummary');
        let selectedFlowCandidateSrcPort = '';
        const spaEnrollmentTypeWrap = document.getElementById('spaEnrollmentTypeWrap');
        const spaEnrollmentTypeRadios = document.querySelectorAll('input[name="spa_enrollment_error_type"]');
        const spaEnrollmentTypeLabels = document.querySelectorAll('label[for="spa-enrollment-cert"], label[for="spa-enrollment-saml"]');
        const evtxScanLimitWrap = document.getElementById('evtxScanLimitWrap');
        const evtxScanLimit = document.getElementById('evtxScanLimit');
        const spaOnlyChecks = document.querySelectorAll('.spa-only-check');
        const showFullCachedConfig = document.getElementById('showFullCachedConfig');
        const enableAiInsight = document.getElementById('enableAiInsight');
        const showFullCachedConfigWrap = document.getElementById('cachedConfigOptionWrap');
        const cachedConfigSearchWrap = document.getElementById('cachedConfigSearchWrap');
        const cachedConfigQuickActionAnchorTop = document.getElementById('cachedConfigQuickActionAnchorTop');
        const ztaQuickActionAnchorAfterMode = document.getElementById('ztaQuickActionAnchorAfterMode');
        const ztaQuickActionAnchorAfterEnrollment = document.getElementById('ztaQuickActionAnchorAfterEnrollment');
        const enrollmentQuickActionAnchor = document.getElementById('enrollmentQuickActionAnchor');
        const spaChecksQuickActionAnchor = document.getElementById('spaChecksQuickActionAnchor');
        const moduleSelectionWrap = document.getElementById('moduleSelectionWrap');
        const aiInsightToggleWrap = document.getElementById('aiInsightToggleWrap');
        const cachedConfigQuickActionWrap = document.getElementById('cachedConfigQuickActionWrap');
        const runCachedConfigAnalysis = document.getElementById('runCachedConfigAnalysis');
        const cachedConfigSearch = document.getElementById('cachedConfigSearch');
        const runCachedConfigSearch = document.getElementById('runCachedConfigSearch');
        const resultContent = document.getElementById('resultContent');
        const resultSearchInput = document.getElementById('resultSearchInput');
        const clearResultSearch = document.getElementById('clearResultSearch');
        const resultSearchCount = document.getElementById('resultSearchCount');
        const serverConnectivitySummaryWrap = document.getElementById('serverConnectivitySummaryWrap');
        const serverConnectivityDiagram = document.getElementById('serverConnectivityDiagram');
        const serverConnectivityStatusChecks = document.getElementById('serverConnectivityStatusChecks');
        const serverConnectivityDownloads = document.getElementById('serverConnectivityDownloads');
        const serverConnectivityTimeRange = document.getElementById('serverConnectivityTimeRange');
        const serverConnectivityTotalHits = document.getElementById('serverConnectivityTotalHits');
        const duoPostureFlowSummaryWrap = document.getElementById('duoPostureFlowSummaryWrap');
        const duoPostureFlowSummaryBody = document.getElementById('duoPostureFlowSummaryBody');
        const duoPostureFlowFilter = document.getElementById('duoPostureFlowFilter');
        const duoPostureFlowTotalPatterns = document.getElementById('duoPostureFlowTotalPatterns');
        const duoPostureFlowTimeRange = document.getElementById('duoPostureFlowTimeRange');
        const configSyncSummaryWrap = document.getElementById('configSyncSummaryWrap');
        const configSyncEnrollment = document.getElementById('configSyncEnrollment');
        const configSyncTimeRange = document.getElementById('configSyncTimeRange');
        const configSyncVerdict = document.getElementById('configSyncVerdict');
        const configSyncStatCards = document.getElementById('configSyncStatCards');
        const configSyncScheduler = document.getElementById('configSyncScheduler');
        const configSyncAttempts = document.getElementById('configSyncAttempts');
        const configSyncDownloads = document.getElementById('configSyncDownloads');
        const eventViewerSummaryWrap = document.getElementById('eventViewerSummaryWrap');
        const eventViewerSubtitle = document.getElementById('eventViewerSubtitle');
        const eventViewerTimeRange = document.getElementById('eventViewerTimeRange');
        const eventViewerNote = document.getElementById('eventViewerNote');
        const eventViewerStatCards = document.getElementById('eventViewerStatCards');
        const eventViewerTopEvents = document.getElementById('eventViewerTopEvents');
        const eventViewerTable = document.getElementById('eventViewerTable');
        const eventViewerDownloads = document.getElementById('eventViewerDownloads');
        const tndSummaryWrap = document.getElementById('tndSummaryWrap');
        const tndOverallStatus = document.getElementById('tndOverallStatus');
        const tndFlowCards = document.getElementById('tndFlowCards');
        const tndPauseTableWrap = document.getElementById('tndPauseTableWrap');
        const tndWarnings = document.getElementById('tndWarnings');
        const userPauseSummaryWrap = document.getElementById('userPauseSummaryWrap');
        const userPauseOverallStatus = document.getElementById('userPauseOverallStatus');
        const userPauseFlowCards = document.getElementById('userPauseFlowCards');
        const userPausePauseTableWrap = document.getElementById('userPausePauseTableWrap');
        const userPauseWarnings = document.getElementById('userPauseWarnings');
        const ztaSummaryPanel = document.getElementById('ztaSummaryPanel');
        const ztaSummaryHeadline = document.getElementById('ztaSummaryHeadline');
        const ztaSummaryVerdict = document.getElementById('ztaSummaryVerdict');
        const ztaSummaryHint = document.getElementById('ztaSummaryHint');
        const ztaSummaryTiles = document.getElementById('ztaSummaryTiles');
        const aiInsightCard = document.getElementById('aiInsightCard');
        const bundleInsightPanel = document.getElementById('bundleInsightPanel');
        const bundleInsightOs = document.getElementById('bundleInsightOs');
        const bundleInsightClientVersion = document.getElementById('bundleInsightClientVersion');
        const bundleInsightOrgIds = document.getElementById('bundleInsightOrgIds');
        const bundleInsightEnrollmentMethod = document.getElementById('bundleInsightEnrollmentMethod');
        const bundleInsightTrace = document.getElementById('bundleInsightTrace');
        const bundleInsightDuoTrace = document.getElementById('bundleInsightDuoTrace');
        const bundleInsightDuoTimeframe = document.getElementById('bundleInsightDuoTimeframe');
        const bundleInsightTndDetected = document.getElementById('bundleInsightTndDetected');
        const bundleInsightSrvConfigDetected = document.getElementById('bundleInsightSrvConfigDetected');
        const bundleInsightTimeframe = document.getElementById('bundleInsightTimeframe');
        const bundleInsightMethodsBody = document.getElementById('bundleInsightMethodsBody');
        const bundleInsightHealthBody = document.getElementById('bundleInsightHealthBody');
        const openAgentChatBtn = document.getElementById('openAgentChatBtn');
        const aiInsightVerdict = document.getElementById('aiInsightVerdict');
        const aiInsightConfidenceBadge = document.getElementById('aiInsightConfidenceBadge');
        const aiInsightConfidence = document.getElementById('aiInsightConfidence');
        const aiInsightKeyEvidence = document.getElementById('aiInsightKeyEvidence');
        const aiInsightDetails = document.getElementById('aiInsightDetails');
        const aiInsightSummary = document.getElementById('aiInsightSummary');
        const aiInsightRootCause = document.getElementById('aiInsightRootCause');
        const aiInsightEvidence = document.getElementById('aiInsightEvidence');
        const aiInsightActions = document.getElementById('aiInsightActions');
        const aiInsightGaps = document.getElementById('aiInsightGaps');
        const aiInsightArticlesWrap = document.getElementById('aiInsightArticlesWrap');
        const aiInsightArticles = document.getElementById('aiInsightArticles');
        const aiInsightDownloadBtn = document.getElementById('aiInsightDownloadBtn');
        const aiInsightCopyBtn = document.getElementById('aiInsightCopyBtn');
        const agentChatCard = document.getElementById('agentChatCard');
        const agentChatStatus = document.getElementById('agentChatStatus');
        const agentChatMessages = document.getElementById('agentChatMessages');
        const agentChatForm = document.getElementById('agentChatForm');
        const agentChatInput = document.getElementById('agentChatInput');
        const agentChatSendBtn = document.getElementById('agentChatSendBtn');
        const toggleOutputSize = document.getElementById('toggleOutputSize');
        const dartFile = document.getElementById('dartFile');
        const mainInitiateButton = document.getElementById('mainInitiateButton');
        const scrollToTopBtn = document.getElementById('scrollToTopBtn');
        const orgIdPreview = document.getElementById('orgIdPreview');
        const orgIdPreviewText = document.getElementById('orgIdPreviewText');
        const uploadForm = document.getElementById('uploadForm');
        const feedbackPanel = document.getElementById('feedbackPanel');
        const feedbackForm = document.getElementById('feedbackForm');
        const feedbackOs = document.getElementById('feedbackOs');
        const feedbackComponent = document.getElementById('feedbackComponent');
        const feedbackIssue = document.getElementById('feedbackIssue');
        const feedbackSrNumber = document.getElementById('feedbackSrNumber');
        const feedbackDartFileName = document.getElementById('feedbackDartFileName');
        const feedbackScreenshots = document.getElementById('feedbackScreenshots');
        const feedbackSubmitButton = document.getElementById('feedbackSubmitButton');
        const feedbackSubmitText = document.getElementById('feedbackSubmitText');
        const btnText = document.getElementById('btnText');
        const btnLoader = document.getElementById('btnLoader');
        const analysisIndicator = document.getElementById('analysisIndicator');
        const analysisIndicatorText = document.getElementById('analysisIndicatorText');
        const analysisIndicatorPulse = document.getElementById('analysisIndicatorPulse');
        const resultArea = document.getElementById('resultArea');
        const resultHeaderRow = document.getElementById('resultHeaderRow');
        const resultSearchRow = document.getElementById('resultSearchRow');
        const resultOutputPanel = document.getElementById('resultOutputPanel');
        const resultTitle = document.getElementById('resultTitle');
        const copyResultButton = document.getElementById('copyResultButton');
        const resultDownloadLink = document.getElementById('resultDownloadLink');
        const enrollmentResultDownloadLink = document.getElementById('enrollmentResultDownloadLink');
        const enrollmentFlowVisualButton = document.getElementById('enrollmentFlowVisualButton');
        const enrollmentAttemptsWrap = document.getElementById('enrollmentAttemptsWrap');
        const cachedConfigDownloadLink = document.getElementById('cachedConfigDownloadLink');
        const transactionDownloadLink = document.getElementById('transactionDownloadLink');
        let pendingTransactionAnalysis = null;
        let pendingSrvTransactionAnalysis = null;
        let selectedSrvFlowIdentifier = '';
        let copyResultButtonResetTimer = null;
        let latestResultRawText = '';
        let latestResultHighlightEnabled = true;
        let currentResultMatchIndex = -1;
        let latestSpaCheckOption = '';
        let analysisIndicatorResetTimer = null;
        let resultDownloadObjectUrl = '';
        let enrollmentResultDownloadObjectUrl = '';
        let latestEnrollmentFlowPayload = null;
        let cachedConfigDownloadObjectUrl = '';
        let transactionDownloadObjectUrl = '';
        let serverConnectivitySummaryDownloadUrls = [];
        let duoPostureSummaryDownloadUrls = [];
        let configSyncSummaryDownloadUrls = [];
        let eventViewerSummaryDownloadUrls = [];
        let aiInsightCopyResetTimer = null;
        let latestAiInsightJson = null;
        let currentAnalysisSessionId = '';
        let agentChatHistory = [];
        let detectedBundleOperatingSystem = '';

        const CHAT_ONLY_UI_MODE = false;

        const criticalLinePattern = /(\berror\b|\berrors\b|\bfailed\b|\bfail\b|\bfailure\b|\bfailures\b|\bfailer\b|\btimeout\b|\btimeouts\b|\btimed\s*out\b|\bexception\b|\bclosing\s+flow\b|\bunreachable\b|\bconnectivity\b|\bconnection\b|network\s+change(?:\s+detection)?|keepalivetimeout|tile\s+status\s+updated\s+to:\s*server\s+connectivity\s+error|new\s+redirected\s+flow|\bproxy_connect_state\b|\bbootstrap\b|\bdeviceregistration\b|\bdharegistration\b|\bdhaenrollment\b|\bdhaenrollmentnotification\b|\bacmeenrollment\b|sent\s+config\s+sync\s+request\s+for\s+enrollment|received\s+sync\s+response\s+with\s+http_status|config\s+sync\s+was\s+(?:successful|failed)|config\s+sync\s+request|sync\s+response|failures\s+since\s+last\s+successful\s+sync)/i;
        const configSyncPhrasePattern = /(sent\s+config\s+sync\s+request\s+for\s+enrollment|received\s+sync\s+response\s+with\s+http_status|config\s+sync\s+was\s+(?:successful|failed)|seconds\s+before\s+next\s+config\s+sync)/gi;
        const enrollmentStatsPhrasePattern = /(\bBootstrap\b|\bAuthentication\b|\bDevice\s*Registration\b|DhaRegistration|\bDHA\s*Registration\b|\bDHA\s*Enrollment\b|\bDHA\s*Enrollment\s*Notification\b|\bACME\s*Enrollment\b|\bPersist\s*Enrollment\b|actionSendDhaRegistration(?:Request|Response)\(\)|dhaEnrollmentInit|actionSendBootstrapRequest\(\)\s+Using\s+client\s+certificate|Using\s+client\s+certificate\.?)/i;
        const detectionStatusLinePattern = /\bDetection\s+Status\s*:/i;
        const suppressedOutputLinePattern = /^\s*Cisco\s+Secure\s+Client\/Zero\s+Trust\s+Access\/Logs\/ZeroTrustAccess\.log(?:\:L\d+)?\s*$/i;
        const outputLinePrefixPattern = /^\s*Cisco\s+Secure\s+Client\/Zero\s+Trust\s+Access\/Logs\/ZeroTrustAccess\.log\:L\d+\s*/i;

        function normalizeOutputLine(line) {
            return String(line || '').replace(outputLinePrefixPattern, '').trimStart();
        }

        function stripSuppressedOutputLines(text) {
            return String(text || '')
                .split(String.fromCharCode(10))
                .map((line) => normalizeOutputLine(line))
                .filter((line) => !suppressedOutputLinePattern.test(String(line || '')))
                .join(String.fromCharCode(10));
        }

        function isCriticalLogLine(line) {
            return criticalLinePattern.test(String(line || ''));
        }

        function isDetectionStatusLine(line) {
            return detectionStatusLinePattern.test(String(line || ''));
        }

        function isConfigurationSyncHighlightMode() {
            return latestSpaCheckOption === 'Check Configuration Sync';
        }

        function isEnrollmentErrorsHighlightMode() {
            return latestSpaCheckOption === 'Check Enrollment Errors';
        }

        function applyConfigSyncPhraseHighlight(renderedLine) {
            return String(renderedLine || '').replace(
                configSyncPhrasePattern,
                (match) => `<strong class="font-bold text-rose-300">${match}</strong>`
            );
        }

        function escapeHtml(value) {
            return String(value || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function escapeRegExp(value) {
            return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }

        function truncateText(value, maxLength) {
            const text = String(value == null ? '' : value);
            if (text.length <= maxLength) {
                return text;
            }
            return text.slice(0, Math.max(0, maxLength - 1)) + '\u2026';
        }

        function renderFlowSequenceSvg(model) {
            const events = (model && model.events) || [];
            const leftX = 280;
            const rightX = 820;
            const midX = (leftX + rightX) / 2;
            const topY = 100;
            const rowH = 64;
            const width = 1100;
            const height = topY + 30 + Math.max(events.length, 1) * rowH + 24;
            const lifelineBottom = height - 18;
            const parts = [];

            parts.push('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + width + ' ' + height + '" width="100%" style="min-width:1000px">');
            parts.push('<defs>'
                + '<marker id="fa-arrow-out" markerWidth="10" markerHeight="8" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L8,3 L0,6 Z" fill="#38bdf8"/></marker>'
                + '<marker id="fa-arrow-in" markerWidth="10" markerHeight="8" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L8,3 L0,6 Z" fill="#34d399"/></marker>'
                + '<marker id="fa-arrow-both-r" markerWidth="10" markerHeight="8" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L8,3 L0,6 Z" fill="#fbbf24"/></marker>'
                + '<marker id="fa-arrow-both-l" markerWidth="10" markerHeight="8" refX="2" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M8,0 L0,3 L8,6 Z" fill="#fbbf24"/></marker>'
                + '<marker id="fa-arrow-out-err" markerWidth="10" markerHeight="8" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L8,3 L0,6 Z" fill="#f87171"/></marker>'
                + '<marker id="fa-arrow-in-err" markerWidth="10" markerHeight="8" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L8,3 L0,6 Z" fill="#f87171"/></marker>'
                + '</defs>');

            parts.push('<line x1="' + leftX + '" y1="' + topY + '" x2="' + leftX + '" y2="' + lifelineBottom + '" stroke="#334155" stroke-width="2" stroke-dasharray="4 5"/>');
            parts.push('<line x1="' + rightX + '" y1="' + topY + '" x2="' + rightX + '" y2="' + lifelineBottom + '" stroke="#334155" stroke-width="2" stroke-dasharray="4 5"/>');

            const actorBox = function (cx, title, fill, stroke, titleColor) {
                const w = 180;
                const h = 46;
                const x = cx - w / 2;
                const y = 30;
                return '<g>'
                    + '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="9" fill="' + fill + '" stroke="' + stroke + '" stroke-width="1.6"/>'
                    + '<text x="' + cx + '" y="' + (y + 29) + '" text-anchor="middle" fill="' + titleColor + '" font-size="15" font-weight="700" font-family="monospace">' + escapeHtml(title) + '</text>'
                    + '</g>';
            };
            parts.push(actorBox(leftX, model.clientLabel || 'ZTA Client', 'rgba(2,132,199,0.20)', '#0ea5e9', '#e0f2fe'));
            parts.push(actorBox(rightX, model.proxyLabel || 'Z Proxy', 'rgba(16,185,129,0.16)', '#10b981', '#d1fae5'));

            if (!events.length) {
                parts.push('<text x="' + midX + '" y="' + (topY + 60) + '" text-anchor="middle" fill="#94a3b8" font-size="13" font-family="monospace">No transaction events were parsed for this flow.</text>');
            }

            // Split a label into stacked lines: main label, an optional bracketed
            // detail line (everything after the em-dash separator) and, for
            // client-side processing steps, a "client-side processing" symbol line.
            function labelLinesFor(ev) {
                const full = String(ev.label == null ? '' : ev.label);
                const segs = full.split(' \u2014 ');
                const lines = [{ text: truncateText(segs[0], 64), cls: 'main' }];
                if (segs.length > 1) {
                    lines.push({ text: '(' + truncateText(segs.slice(1).join(' \u2014 '), 68) + ')', cls: ev.error ? 'err' : 'detail' });
                }
                if (ev.error) {
                    lines.push({ text: '\u26a0 error / failure', cls: 'err' });
                } else if (ev.direction === 'self') {
                    lines.push({ text: '\u21ba client-side processing', cls: 'note' });
                }
                return lines;
            }

            function renderLabelLines(lines, mainFill, y) {
                const n = lines.length;
                let out = '';
                lines.forEach(function (ln, k) {
                    const ly = y - 9 - (n - 1 - k) * 14;
                    let fill = mainFill, size = 13, weight = 700;
                    if (ln.cls === 'detail') { fill = '#94a3b8'; size = 11.5; weight = 500; }
                    else if (ln.cls === 'note') { fill = '#fbbf24'; size = 11; weight = 600; }
                    else if (ln.cls === 'err') { fill = '#fca5a5'; size = 11; weight = 600; }
                    out += '<text x="' + midX + '" y="' + ly + '" text-anchor="middle" fill="' + fill + '" font-size="' + size + '" font-weight="' + weight + '" font-family="monospace">' + escapeHtml(ln.text) + '</text>';
                });
                return out;
            }

            events.forEach(function (ev, i) {
                const y = topY + 30 + i * rowH;
                parts.push('<g class="fa-row" data-idx="' + i + '">');
                if (ev.timestamp) {
                    parts.push('<text x="12" y="' + (y - 4) + '" fill="#b8c0cc" font-size="12.5" font-weight="500" font-family="monospace">' + escapeHtml(ev.timestamp) + '</text>');
                }
                const isErr = !!ev.error;
                const mainFill = isErr ? '#fca5a5'
                    : ev.direction === 'in' ? '#a7f3d0'
                    : ev.direction === 'out' ? '#bae6fd'
                    : ev.direction === 'both' ? '#fde68a'
                    : '#e2e8f0';
                parts.push(renderLabelLines(labelLinesFor(ev), mainFill, y));
                if (ev.direction === 'in') {
                    const c = isErr ? '#f87171' : '#34d399';
                    const mk = isErr ? 'fa-arrow-in-err' : 'fa-arrow-in';
                    parts.push('<line x1="' + rightX + '" y1="' + y + '" x2="' + (leftX + 2) + '" y2="' + y + '" stroke="' + c + '" stroke-width="1.8" marker-end="url(#' + mk + ')"/>');
                } else if (ev.direction === 'out') {
                    const c = isErr ? '#f87171' : '#38bdf8';
                    const mk = isErr ? 'fa-arrow-out-err' : 'fa-arrow-out';
                    parts.push('<line x1="' + leftX + '" y1="' + y + '" x2="' + (rightX - 2) + '" y2="' + y + '" stroke="' + c + '" stroke-width="1.8" marker-end="url(#' + mk + ')"/>');
                } else if (ev.direction === 'both') {
                    parts.push('<line x1="' + (leftX + 2) + '" y1="' + y + '" x2="' + (rightX - 2) + '" y2="' + y + '" stroke="#fbbf24" stroke-width="1.8" stroke-dasharray="6 4" marker-start="url(#fa-arrow-both-l)" marker-end="url(#fa-arrow-both-r)"/>');
                } else {
                    const gc = isErr ? '#f87171' : '#64748b';
                    parts.push('<path d="M' + (leftX - 6) + ' ' + (y - 6) + ' h30 v12 h-30" fill="none" stroke="' + gc + '" stroke-width="1.5"/>');
                    parts.push('<polygon points="' + (leftX - 6) + ',' + (y + 6) + ' ' + (leftX + 1) + ',' + (y + 2) + ' ' + (leftX + 1) + ',' + (y + 10) + '" fill="' + gc + '"/>');
                }
                // Transparent hit area making the whole row clickable.
                parts.push('<rect class="fa-hit" x="0" y="' + (y - 30) + '" width="' + width + '" height="' + (rowH - 6) + '" fill="transparent"/>');
                parts.push('</g>');
            });

            parts.push('</svg>');
            return parts.join('');
        }

        function buildFlowVisualDocument(model, title) {
            const safeTitle = escapeHtml(title || 'Visual Flow Analyzer');
            const accessType = (model.accessType || '').trim();
            const isSpa = /private/i.test(accessType);
            const accessBadge = accessType
                ? '<div class="access ' + (isSpa ? 'spa' : 'sia') + '">'
                    + escapeHtml(accessType) + '</div>'
                : '';
            const destinationText = model.destination
                + (model.realDestinationIp ? ' (' + model.realDestinationIp + ')' : '');
            const summaryBits = (Array.isArray(model.summaryBits) && model.summaryBits.length
                ? model.summaryBits
                : [
                    'Source: ZTA Client (' + model.process + ', srcPort ' + model.srcPort + ')',
                    'Destination: Z Proxy \u2192 ' + (destinationText || 'Z Proxy'),
                    'Rule: ' + model.ruleType,
                    model.firstTime ? 'From: ' + model.firstTime : '',
                    model.lastTime ? 'To: ' + model.lastTime : '',
                    'Events: ' + model.eventCount,
                ]).filter(Boolean).map(escapeHtml).join('  &nbsp;|&nbsp;  ');
            const proxyName = escapeHtml(model.proxyLabel || 'Z Proxy');
            const clientName = escapeHtml(model.clientLabel || 'ZTA Client');
            const bothLegendLabel = escapeHtml(model.bothLabel || 'Application data');
            const endpoints = Array.isArray(model.endpoints) ? model.endpoints : [];
            const endpointsHtml = endpoints.length
                ? '<div class="endpoints"><div class="eh">ZTA endpoints contacted</div>'
                    + '<table><thead><tr><th>Step</th><th>Method</th><th>URL</th></tr></thead><tbody>'
                    + endpoints.map(function (e) {
                        return '<tr><td>' + escapeHtml(e.label) + '</td>'
                            + '<td>' + escapeHtml(e.method || '') + '</td>'
                            + '<td>' + escapeHtml(e.url) + '</td></tr>';
                    }).join('')
                    + '</tbody></table></div>'
                : '';
            const svg = renderFlowSequenceSvg(model);
            const eventsJson = JSON.stringify((model.events || []).map(function (ev) {
                return { label: ev.label || '', timestamp: ev.timestamp || '', raw: ev.raw || '', logIndex: (typeof ev.logIndex === 'number' ? ev.logIndex : -1), error: !!ev.error };
            })).replace(/<\//g, '<\\/');
            const logJson = JSON.stringify(Array.isArray(model.logLines) ? model.logLines : [])
                .replace(/<\//g, '<\\/');
            return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
                + '<meta name="viewport" content="width=device-width, initial-scale=1">'
                + '<title>' + safeTitle + '</title>'
                + '<style>'
                + 'body{margin:0;background:#0b1220;color:#e2e8f0;font-family:ui-monospace,Menlo,Consolas,monospace;}'
                + '.wrap{max-width:1000px;margin:0 auto;padding:24px;}'
                + 'h1{font-size:14px;letter-spacing:.15em;text-transform:uppercase;color:#7dd3fc;margin:0 0 12px;}'
                + '.access{display:inline-block;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:4px 12px;border-radius:999px;margin:0 0 14px;}'
                + '.access.spa{color:#bbf7d0;background:rgba(16,185,129,.16);border:1px solid rgba(16,185,129,.5);}'
                + '.access.sia{color:#bfdbfe;background:rgba(59,130,246,.16);border:1px solid rgba(59,130,246,.5);}'
                + '.summary{font-size:12px;color:#cbd5e1;margin-bottom:10px;line-height:1.7;}'
                + '.legend{font-size:12px;margin-bottom:16px;display:flex;gap:22px;flex-wrap:wrap;}'
                + '.legend .o{color:#7dd3fc;}.legend .i{color:#6ee7b7;}.legend .s{color:#cbd5e1;}.legend .b{color:#fcd34d;}.legend .e{color:#fca5a5;}'
                + '.diagram{background:#020617;border:1px solid rgba(56,189,248,.25);border-radius:12px;padding:16px;overflow:auto;}'
                + '.toolbar{display:flex;gap:10px;margin:0 0 14px;flex-wrap:wrap;}'
                + '.btn{cursor:pointer;font-family:inherit;font-size:12px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#e2e8f0;background:rgba(56,189,248,.14);border:1px solid rgba(56,189,248,.45);border-radius:8px;padding:8px 14px;}'
                + '.btn:hover{background:rgba(56,189,248,.26);}'
                + '.fa-row{cursor:pointer;}'
                + '.fa-row:hover .fa-hit{fill:rgba(56,189,248,.08);}'
                + '.fa-row.sel .fa-hit{fill:rgba(56,189,248,.14);}'
                + '.hint{font-size:11px;color:#64748b;margin:10px 0 0;letter-spacing:.04em;}'
                + '.detail{margin-top:14px;background:#020617;border:1px solid rgba(56,189,248,.25);border-radius:12px;padding:14px 16px;font-size:12px;}'
                + '.detail .dl{color:#7dd3fc;font-weight:700;margin-bottom:8px;}'
                + '.detail .ts{color:#b8c0cc;font-weight:500;margin-bottom:8px;}'
                + '.detail pre{margin:0;white-space:pre-wrap;word-break:break-word;color:#e2e8f0;line-height:1.6;}'
                + '.detail .muted{color:#64748b;}'
                + '.detail .dh{margin-bottom:8px;}'
                + '.detail .dh .dl{display:inline;margin:0;}'
                + '.logbox{position:relative;max-height:380px;overflow:auto;background:#0b1220;border:1px solid rgba(56,189,248,.18);border-radius:8px;padding:8px 10px;margin-top:10px;font-size:11px;line-height:1.6;}'
                + '.logline{white-space:pre-wrap;word-break:break-word;color:#8b97a8;padding:1px 6px;border-left:2px solid transparent;}'
                + '.logline.hl{background:rgba(251,191,36,.16);color:#fde68a;border-left:2px solid #fbbf24;}'
                + '.logline.hlerr{background:rgba(248,113,113,.16);color:#fecaca;border-left:2px solid #f87171;}'
                + '.endpoints{margin:6px 0 16px;background:#020617;border:1px solid rgba(56,189,248,.2);border-radius:12px;padding:12px 14px;}'
                + '.endpoints .eh{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#7dd3fc;font-weight:700;margin-bottom:10px;}'
                + '.endpoints table{width:100%;border-collapse:collapse;font-size:11.5px;}'
                + '.endpoints th{text-align:left;color:#94a3b8;font-weight:600;padding:4px 8px;border-bottom:1px solid rgba(148,163,184,.25);}'
                + '.endpoints td{padding:5px 8px;border-bottom:1px solid rgba(148,163,184,.08);color:#cbd5e1;word-break:break-all;vertical-align:top;}'
                + '.endpoints td:nth-child(2){color:#7dd3fc;font-weight:700;white-space:nowrap;}'
                + '.endpoints td:last-child{color:#a7f3d0;}'
                + '</style></head><body><div class="wrap">'
                + '<h1>' + safeTitle + '</h1>'
                + accessBadge
                + '<div class="summary">' + summaryBits + '</div>'
                + '<div class="legend">'
                + '<span class="o">&#8594; ' + clientName + ' &#8594; ' + proxyName + ' (request / setup)</span>'
                + '<span class="i">&#8592; ' + proxyName + ' &#8594; ' + clientName + ' (response / connected)</span>'
                + '<span class="s">&#8635; Client-side processing</span>'
                + '<span class="b">&#8596; ' + bothLegendLabel + '</span>'
                + '<span class="e">&#9888; Error / failure</span>'
                + '</div>'
                + endpointsHtml
                + '<div class="toolbar">'
                + '<button id="fa-dl-svg" class="btn" type="button">Download SVG</button>'
                + '<button id="fa-dl-png" class="btn" type="button">Download PNG</button>'
                + '</div>'
                + '<div class="diagram">' + svg + '</div>'
                + '<p class="hint">Tip: click any step or arrow to view the exact raw log line it was parsed from.</p>'
                + '<div id="fa-detail" class="detail"><div class="muted">Click any step or arrow above to view its raw log line.</div></div>'
                + '</div>'
                + '<script>window.__FA_EVENTS__=' + eventsJson + ';<\/script>'
                + '<script>window.__FA_LOG__=' + logJson + ';<\/script>'
                + '<script>' + flowDownloadScript() + '<\/script>'
                + '<script>' + flowInteractScript() + '<\/script>'
                + '</body></html>';
        }

        function flowInteractScript() {
            return '(function(){'
                + 'var events=window.__FA_EVENTS__||[];'
                + 'var log=window.__FA_LOG__||[];'
                + 'var hasLog=log.length>0;'
                + 'function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}'
                + 'var panel=document.getElementById("fa-detail");'
                + 'var box=null,lineEls=null,header=null;'
                + 'if(hasLog&&panel){'
                +   'panel.innerHTML="<div id=\\"fa-dh\\" class=\\"dh muted\\">Click any step or arrow above to highlight it within the full log.</div><div id=\\"fa-logbox\\" class=\\"logbox\\"></div>";'
                +   'header=document.getElementById("fa-dh");'
                +   'box=document.getElementById("fa-logbox");'
                +   'var h="";for(var j=0;j<log.length;j++){h+="<div class=\\"logline\\" data-i=\\""+j+"\\">"+esc(log[j])+"</div>";}'
                +   'box.innerHTML=h;'
                +   'lineEls=box.querySelectorAll(".logline");'
                + '}'
                + 'function show(i){var ev=events[i];if(!ev||!panel)return;'
                +   'var rows=document.querySelectorAll(".fa-row");'
                +   'for(var k=0;k<rows.length;k++){rows[k].classList.remove("sel");}'
                +   'if(rows[i])rows[i].classList.add("sel");'
                +   'if(hasLog){'
                +     'if(header)header.innerHTML="<span class=\\"dl\\">"+esc(ev.label)+"</span>"+(ev.timestamp?" &nbsp;<span class=\\"ts\\">"+esc(ev.timestamp)+"</span>":"");'
                +     'var cls=ev.error?"hlerr":"hl";'
                +     'for(var m=0;m<lineEls.length;m++){lineEls[m].classList.remove("hl");lineEls[m].classList.remove("hlerr");}'
                +     'var li=(typeof ev.logIndex==="number")?ev.logIndex:-1;'
                +     'var scrollIdx=li;'
                +     'if(ev.error){'
                +       'var errRe=/(?:^|[^A-Za-z])E\\/(?:\\s|$)|\\bError\\b|\\bfailed\\b|\\bfailure\\b|InitializationError|None of the/i;'
                +       'var firstErr=-1;'
                +       'for(var e=0;e<lineEls.length;e++){if(errRe.test(String(log[e]||""))){lineEls[e].classList.add("hlerr");if(firstErr<0)firstErr=e;}}'
                +       'if(firstErr>=0)scrollIdx=firstErr;'
                +     '}'
                +     'if(li>=0&&lineEls[li]){lineEls[li].classList.add(cls);}'
                +     'if(scrollIdx>=0&&lineEls[scrollIdx]){box.scrollTop=lineEls[scrollIdx].offsetTop-box.clientHeight/2+lineEls[scrollIdx].clientHeight/2;}'
                +   '}else{'
                +     'var html="<div class=\\"dl\\">"+esc(ev.label)+"</div>";'
                +     'if(ev.timestamp)html+="<div class=\\"ts\\">"+esc(ev.timestamp)+"</div>";'
                +     'if(ev.raw)html+="<pre>"+esc(ev.raw)+"</pre>";'
                +     'else html+="<div class=\\"muted\\">This is an aggregated step with no single source log line.</div>";'
                +     'panel.innerHTML=html;'
                +   '}'
                + '}'
                + 'document.querySelectorAll(".fa-row").forEach(function(g){g.addEventListener("click",function(){var i=parseInt(g.getAttribute("data-idx"),10);if(!isNaN(i))show(i);});});'
                + '})();';
        }

        function flowDownloadScript() {
            return '(function(){'
                + 'var slug=(document.title||"visual-flow").replace(/[^a-z0-9._-]+/gi,"_").replace(/^_+|_+$/g,"")||"visual-flow";'
                + 'function svgEl(){return document.querySelector(".diagram svg");}'
                + 'function save(blob,name){var u=URL.createObjectURL(blob);var a=document.createElement("a");a.href=u;a.download=name;document.body.appendChild(a);a.click();document.body.removeChild(a);setTimeout(function(){URL.revokeObjectURL(u);},1000);}'
                + 'function dims(svg){var vb=(svg.getAttribute("viewBox")||"").split(/\\s+/).map(Number);return {w:vb[2]||1100,h:vb[3]||600};}'
                + 'var sb=document.getElementById("fa-dl-svg");'
                + 'if(sb)sb.addEventListener("click",function(){var svg=svgEl();if(!svg)return;var data="<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n"+svg.outerHTML;save(new Blob([data],{type:"image/svg+xml;charset=utf-8"}),slug+".svg");});'
                + 'var pb=document.getElementById("fa-dl-png");'
                + 'if(pb)pb.addEventListener("click",function(){var svg=svgEl();if(!svg)return;var d=dims(svg);var scale=2;var clone=svg.cloneNode(true);clone.setAttribute("width",d.w);clone.setAttribute("height",d.h);var blob=new Blob(["<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n"+clone.outerHTML],{type:"image/svg+xml;charset=utf-8"});var url=URL.createObjectURL(blob);var img=new Image();img.onload=function(){var c=document.createElement("canvas");c.width=d.w*scale;c.height=d.h*scale;var ctx=c.getContext("2d");ctx.fillStyle="#020617";ctx.fillRect(0,0,c.width,c.height);ctx.scale(scale,scale);ctx.drawImage(img,0,0);URL.revokeObjectURL(url);c.toBlob(function(b){if(b)save(b,slug+".png");},"image/png");};img.onerror=function(){URL.revokeObjectURL(url);alert("Could not render PNG. Try Download SVG instead.");};img.src=url;});'
                + '})();';
        }

        function openFlowVisualTab(model, title) {
            const html = buildFlowVisualDocument(model, title);
            const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
            const objectUrl = URL.createObjectURL(blob);
            const newTab = window.open(objectUrl, '_blank');
            if (!newTab) {
                alert('Please allow pop-ups for this site to open the Visual Flow Analyzer in a new tab.');
            }
            window.setTimeout(function () {
                URL.revokeObjectURL(objectUrl);
            }, 120000);
        }

        function applySearchHighlight(escapedLine, searchTerm, startIndex = 0) {
            const needle = String(searchTerm || '').trim();
            if (!needle) {
                return { html: escapedLine, count: 0 };
            }

            const escapedNeedle = escapeHtml(needle);
            if (!escapedNeedle) {
                return { html: escapedLine, count: 0 };
            }

            const regex = new RegExp(escapeRegExp(escapedNeedle), 'gi');
            let matchCount = 0;
            const highlighted = escapedLine.replace(regex, (match) => {
                const matchIndex = startIndex + matchCount;
                matchCount += 1;
                return `<mark class="sr-match bg-amber-300/80 text-slate-900 rounded px-0.5" data-sr-match="${matchIndex}">${match}</mark>`;
            });

            return { html: highlighted, count: matchCount };
        }

        function updateResultSearchCount(matchCount, hasSearchTerm) {
            if (!resultSearchCount) {
                return;
            }

            if (!hasSearchTerm) {
                resultSearchCount.textContent = 'Search output';
                return;
            }

            if (!matchCount) {
                resultSearchCount.textContent = 'No matches';
                return;
            }

            if (currentResultMatchIndex >= 0 && currentResultMatchIndex < matchCount) {
                resultSearchCount.textContent = `${currentResultMatchIndex + 1} of ${matchCount}`;
                return;
            }

            resultSearchCount.textContent = matchCount === 1 ? '1 match' : `${matchCount} matches`;
        }

        function getResultMatchMarks() {
            if (!resultContent) {
                return [];
            }
            return Array.prototype.slice.call(resultContent.querySelectorAll('mark.sr-match'));
        }

        function highlightActiveResultMatch() {
            const marks = getResultMatchMarks();
            marks.forEach((mark) => mark.classList.remove('sr-match-active'));
            if (!marks.length) {
                currentResultMatchIndex = -1;
                return;
            }
            if (currentResultMatchIndex < 0 || currentResultMatchIndex >= marks.length) {
                return;
            }
            const active = marks[currentResultMatchIndex];
            active.classList.add('sr-match-active');
            if (typeof active.scrollIntoView === 'function') {
                active.scrollIntoView({ block: 'center', behavior: 'smooth' });
            }
        }

        function moveToResultMatch(direction) {
            const marks = getResultMatchMarks();
            if (!marks.length) {
                updateResultSearchCount(0, true);
                return;
            }
            if (currentResultMatchIndex < 0) {
                currentResultMatchIndex = direction >= 0 ? 0 : marks.length - 1;
            } else {
                currentResultMatchIndex = (currentResultMatchIndex + direction + marks.length) % marks.length;
            }
            highlightActiveResultMatch();
            updateResultSearchCount(marks.length, true);
        }

        function setResultSearchState(isEnabled) {
            if (resultSearchInput) {
                resultSearchInput.disabled = !isEnabled;
                resultSearchInput.classList.toggle('opacity-40', !isEnabled);
                resultSearchInput.classList.toggle('cursor-not-allowed', !isEnabled);
            }
            if (clearResultSearch) {
                clearResultSearch.disabled = !isEnabled;
                clearResultSearch.classList.toggle('opacity-40', !isEnabled);
                clearResultSearch.classList.toggle('cursor-not-allowed', !isEnabled);
            }
            if (!isEnabled) {
                updateResultSearchCount(0, false);
            }
        }

        function reRenderCurrentResultWithSearch() {
            if (!resultContent) {
                return;
            }
            renderResultText(latestResultRawText, latestResultHighlightEnabled);
        }

        function renderResultText(text, enableHighlight = true) {
            const sanitizedText = stripSuppressedOutputLines(text);
            latestResultRawText = String(sanitizedText || '');
            latestResultHighlightEnabled = Boolean(enableHighlight);
            const lines = String(sanitizedText || '').split(String.fromCharCode(10));
            const searchTerm = resultSearchInput ? resultSearchInput.value : '';
            const hasSearchTerm = Boolean(String(searchTerm || '').trim());
            let totalMatches = 0;
            currentResultMatchIndex = -1;

            const html = lines.map((line) => {
                const escapedLine = escapeHtml(line);
                const highlightedResult = applySearchHighlight(escapedLine, searchTerm, totalMatches);
                totalMatches += highlightedResult.count;
                const renderedLine = highlightedResult.html;

                if (isDetectionStatusLine(line)) {
                    return `<strong class="font-bold text-rose-300">${renderedLine}</strong>`;
                }
                if (line.startsWith('Results are ready for download.')) {
                    return `<strong class="font-bold text-emerald-300">${renderedLine}</strong>`;
                }
                if (enableHighlight && isEnrollmentErrorsHighlightMode() && enrollmentStatsPhrasePattern.test(line)) {
                    return `<strong class="font-bold text-rose-300">${renderedLine}</strong>`;
                }
                if (enableHighlight && isConfigurationSyncHighlightMode()) {
                    return applyConfigSyncPhraseHighlight(renderedLine);
                }
                if (enableHighlight && isCriticalLogLine(line)) {
                    return `<strong class="font-bold text-rose-300">${renderedLine}</strong>`;
                }
                return renderedLine;
            }).join(String.fromCharCode(10));
            resultContent.innerHTML = html;
            updateResultSearchCount(totalMatches, hasSearchTerm);

            const hasOutput = String(resultContent.textContent || '').trim().length > 0;
            setResultSearchState(hasOutput);
        }

        function emphasizeCriticalLinesForDownload(text) {
            return stripSuppressedOutputLines(text)
                .split(String.fromCharCode(10))
                .map((line) => (isCriticalLogLine(line) ? `**${line}**` : line))
                .join(String.fromCharCode(10));
        }

        function shouldEnableCriticalHighlight(moduleValue, ztaModeValue, spaCheckValue, srvCheckOptionValue) {
            return (
                moduleValue === 'ZTA'
                && ztaModeValue === 'SPA'
                && (
                    spaCheckValue === 'Check TCP or UDP Flow'
                    || spaCheckValue === 'Check Configuration Sync'
                    || spaCheckValue === 'Check Server Connectivity Errors'
                    || (spaCheckValue === 'SRV Check' && srvCheckOptionValue === 'SRV Flow')
                )
            );
        }

        function maybeEmphasizeForDownload(text, enabled) {
            return enabled ? emphasizeCriticalLinesForDownload(text) : stripSuppressedOutputLines(text);
        }

        function buildCriticalHighlightHtml(text) {
            const lines = stripSuppressedOutputLines(text).split(String.fromCharCode(10));
            return lines.map((line) => {
                const escapedLine = escapeHtml(line);
                if (isCriticalLogLine(line)) {
                    return `<strong style="color:#fda4af; font-weight:700;">${escapedLine}</strong>`;
                }
                return escapedLine;
            }).join(String.fromCharCode(10));
        }

        async function fetchTransactionTraceLinesForSourcePort(srcPort) {
            const selectedFile = dartFile.files && dartFile.files[0] ? dartFile.files[0] : null;
            const selectedModule = document.querySelector('input[name="module"]:checked');
            const selectedZtaMode = document.querySelector('input[name="zta_access_mode"]:checked');
            const selectedSpaCheck = document.querySelector('input[name="spa_check_option"]:checked');

            if (!selectedFile || !selectedModule || !selectedZtaMode || !selectedSpaCheck) {
                return [];
            }

            const formData = new FormData();
            formData.append('file', selectedFile);
            formData.append('module', selectedModule.value);
            appendClientTimezoneOffset(formData);
            formData.append('zta_access_mode', selectedZtaMode.value);
            formData.append('spa_check_option', selectedSpaCheck.value);
            appendEvtxScanDepth(formData, selectedSpaCheck.value);
            formData.append('spa_target_value', spaTargetInput.value.trim());
            formData.append('flow_selected_src_port', String(srcPort || '').trim());

            if (spaFlowDestinationPort) {
                formData.append('flow_filter_destination_port', spaFlowDestinationPort.value.trim());
            }

            const flowFilterTimeStart = buildFlowFilterDateTimeValue(
                spaFlowStartDate.value,
                spaFlowStartHour.value,
                spaFlowStartMinute.value,
                false
            );
            const flowFilterTimeEnd = buildFlowFilterDateTimeValue(
                spaFlowEndDate.value,
                spaFlowEndHour.value,
                spaFlowEndMinute.value,
                true
            );
            formData.append('flow_filter_time_start', flowFilterTimeStart);
            formData.append('flow_filter_time_end', flowFilterTimeEnd);

            formData.append('show_full_cached_config', showFullCachedConfig.checked ? '1' : '0');
            formData.append('cached_config_search_term', cachedConfigSearch.value.trim());

            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData,
                });
                const payload = await response.json();
                if (!response.ok || !payload || !payload.details) {
                    return [];
                }
                const tracesByPort = flowUtils.parseSelectedFlowTraceFromOutput(payload.details);
                return tracesByPort[String(srcPort || '').trim()] || [];
            } catch (_error) {
                return [];
            }
        }

        function wrapResultHtmlDocument(innerPreHtml) {
            return [
                '<!doctype html>',
                '<html lang="en">',
                '<head><meta charset="utf-8"><title>DartHawk Result</title></head>',
                '<body style="background:#020b18; color:#dbeafe; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; padding:16px;">',
                '<pre style="white-space:pre-wrap; line-height:1.5; margin:0;">',
                innerPreHtml,
                '</pre>',
                '</body>',
                '</html>',
            ].join('');
        }

        function setResultDownloadLinkState(isVisible, filename = '', content = '', preserveCriticalColor = false) {
            if (!resultDownloadLink) {
                return;
            }

            if (resultDownloadObjectUrl) {
                URL.revokeObjectURL(resultDownloadObjectUrl);
                resultDownloadObjectUrl = '';
            }

            if (!isVisible || !content) {
                resultDownloadLink.classList.add('hidden');
                resultDownloadLink.removeAttribute('href');
                resultDownloadLink.removeAttribute('download');
                return;
            }

            const sanitizedContent = stripSuppressedOutputLines(content);
            let blob = null;
            let resolvedFilename = filename || 'analysis_result.log';
            if (preserveCriticalColor) {
                const htmlBody = buildCriticalHighlightHtml(sanitizedContent);
                blob = new Blob([wrapResultHtmlDocument(htmlBody)], { type: 'text/html;charset=utf-8' });
                if (resolvedFilename.toLowerCase().endsWith('.log')) {
                    resolvedFilename = resolvedFilename.slice(0, -4) + '.html';
                }
            } else {
                const normalizedFilename = String(resolvedFilename || '').toLowerCase();
                const mimeType = normalizedFilename.endsWith('.csv')
                    ? 'text/csv;charset=utf-8'
                    : 'text/plain;charset=utf-8';
                blob = new Blob([sanitizedContent], { type: mimeType });
            }
            resultDownloadObjectUrl = URL.createObjectURL(blob);
            resultDownloadLink.href = resultDownloadObjectUrl;
            resultDownloadLink.download = resolvedFilename;
            resultDownloadLink.classList.remove('hidden');
        }

        function setEnrollmentResultDownloadLinkState(isVisible, filename = '', content = '') {
            if (!enrollmentResultDownloadLink) {
                return;
            }

            if (enrollmentResultDownloadObjectUrl) {
                URL.revokeObjectURL(enrollmentResultDownloadObjectUrl);
                enrollmentResultDownloadObjectUrl = '';
            }

            if (!isVisible || !content) {
                enrollmentResultDownloadLink.classList.add('hidden');
                enrollmentResultDownloadLink.removeAttribute('href');
                enrollmentResultDownloadLink.removeAttribute('download');
                return;
            }

            const sanitizedContent = stripSuppressedOutputLines(content);
            const blob = new Blob([sanitizedContent], { type: 'text/plain;charset=utf-8' });
            enrollmentResultDownloadObjectUrl = URL.createObjectURL(blob);
            enrollmentResultDownloadLink.href = enrollmentResultDownloadObjectUrl;
            enrollmentResultDownloadLink.download = filename || 'enrollment_result.log';
            enrollmentResultDownloadLink.classList.remove('hidden');
        }

        function setEnrollmentFlowVisualButtonState(isVisible, payload = null) {
            latestEnrollmentFlowPayload = (isVisible && payload && Array.isArray(payload.attempts) && payload.attempts.length)
                ? payload
                : null;
            if (!enrollmentFlowVisualButton) {
                return;
            }
            if (latestEnrollmentFlowPayload) {
                enrollmentFlowVisualButton.classList.remove('hidden');
            } else {
                enrollmentFlowVisualButton.classList.add('hidden');
            }
        }

        if (enrollmentFlowVisualButton) {
            enrollmentFlowVisualButton.addEventListener('click', function () {
                if (!latestEnrollmentFlowPayload || !flowUtils || typeof flowUtils.buildEnrollmentFlowModel !== 'function') {
                    return;
                }
                const model = flowUtils.buildEnrollmentFlowModel(latestEnrollmentFlowPayload);
                const methodLabel = latestEnrollmentFlowPayload.auth_method === 'Cert' ? 'Cert' : 'SAML';
                openFlowVisualTab(model, 'Visual Flow Analyzer \u00b7 ' + methodLabel + ' Enrollment');
            });
        }

        function resetEnrollmentAttempts() {
            if (enrollmentAttemptsWrap) {
                enrollmentAttemptsWrap.innerHTML = '';
                enrollmentAttemptsWrap.classList.add('hidden');
            }
        }

        function renderEnrollmentAttempts(payload) {
            resetEnrollmentAttempts();
            if (!enrollmentAttemptsWrap || !payload || !Array.isArray(payload.attempts) || !payload.attempts.length) {
                return;
            }

            const attempts = payload.attempts;
            const methodLabel = payload.auth_method === 'Cert' ? 'Cert' : 'SAML';

            const deriveAttemptResult = (attempt) => {
                const lines = Array.isArray(attempt.trace_lines) ? attempt.trace_lines : [];
                for (let i = lines.length - 1; i >= 0; i--) {
                    const match = String(lines[i] || '').match(/Overall result\s*:\s*([A-Za-z]+)/i);
                    if (match) {
                        return match[1].toLowerCase();
                    }
                }
                return '';
            };
            const deriveAttemptTime = (attempt) => {
                const lines = Array.isArray(attempt.trace_lines) ? attempt.trace_lines : [];
                for (let i = 0; i < lines.length; i++) {
                    const match = String(lines[i] || '').match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)/);
                    if (match) {
                        return match[1];
                    }
                }
                return 'Unknown';
            };

            const failedCount = attempts.filter((a) => deriveAttemptResult(a) && deriveAttemptResult(a) !== 'success').length;

            const heading = document.createElement('div');
            heading.className = 'mb-3 flex items-center justify-between';
            const headingTitle = document.createElement('div');
            headingTitle.className = 'text-sky-300 font-bold tracking-wide text-sm uppercase';
            headingTitle.textContent = `${methodLabel} Enrollment Attempts (${attempts.length})`;
            const headingMeta = document.createElement('div');
            headingMeta.className = 'text-xs font-semibold';
            headingMeta.innerHTML = failedCount
                ? `<span class="text-emerald-400">${attempts.length - failedCount} ok</span> \u00b7 <span class="text-red-400">${failedCount} failed</span>`
                : `<span class="text-emerald-400">all ${attempts.length} ok</span>`;
            heading.appendChild(headingTitle);
            heading.appendChild(headingMeta);
            enrollmentAttemptsWrap.appendChild(heading);

            const detectedLabel = payload.auth_method_label
                || (payload.auth_method === 'Cert' ? 'Certificate-based Auth' : 'SAML-based Auth');
            const subtitle = document.createElement('div');
            subtitle.className = 'mb-3 -mt-2 text-xs font-semibold text-slate-400';
            subtitle.textContent = `Auto-detected enrollment type: ${detectedLabel}`;
            enrollmentAttemptsWrap.appendChild(subtitle);

            const scroll = document.createElement('div');
            scroll.className = 'max-h-80 overflow-auto';
            const table = document.createElement('table');
            table.className = 'w-full text-left text-sm';
            table.innerHTML = '<thead><tr class="text-[11px] uppercase tracking-wide text-sky-200/60">'
                + '<th class="py-1 pr-3 font-semibold">#</th>'
                + '<th class="py-1 pr-3 font-semibold">Time</th>'
                + '<th class="py-1 pr-3 font-semibold">Identifier</th>'
                + '<th class="py-1 pr-3 font-semibold">Result</th>'
                + '<th class="py-1 text-right font-semibold">Flow</th></tr></thead>';
            const tbody = document.createElement('tbody');

            attempts.forEach((attempt) => {
                const result = deriveAttemptResult(attempt);
                const isErr = result && result !== 'success';
                const openThis = () => {
                    if (!flowUtils || typeof flowUtils.buildEnrollmentFlowModel !== 'function') {
                        return;
                    }
                    const model = flowUtils.buildEnrollmentFlowModel(payload, attempt.index);
                    if (!model.events.length) {
                        alert('No enrollment request/response events were parsed to visualize for this attempt.');
                        return;
                    }
                    openFlowVisualTab(model, `Visual Flow Analyzer \u00b7 ${methodLabel} Enrollment Attempt ${attempt.index}`);
                };

                const tr = document.createElement('tr');
                tr.className = isErr
                    ? 'cursor-pointer border-t border-red-500/15 hover:bg-red-500/10'
                    : 'cursor-pointer border-t border-sky-500/10 hover:bg-sky-500/10';
                tr.addEventListener('click', openThis);

                const numCell = document.createElement('td');
                numCell.className = 'py-2 pr-3 font-semibold text-sky-100';
                numCell.textContent = String(attempt.index);
                tr.appendChild(numCell);

                const timeCell = document.createElement('td');
                timeCell.className = 'py-2 pr-3 font-mono text-xs text-slate-300';
                timeCell.textContent = deriveAttemptTime(attempt);
                tr.appendChild(timeCell);

                const idCell = document.createElement('td');
                idCell.className = 'py-2 pr-3 font-mono text-xs text-slate-400 break-all';
                idCell.textContent = attempt.identifier || '\u2014';
                tr.appendChild(idCell);

                const resultCell = document.createElement('td');
                resultCell.className = 'py-2 pr-3';
                const resultBadge = document.createElement('span');
                let badgeText;
                let badgeClass;
                if (!result) {
                    badgeText = 'Unknown';
                    badgeClass = 'border-slate-400 bg-slate-100 text-slate-600';
                } else if (result === 'success') {
                    badgeText = 'Success';
                    badgeClass = 'border-emerald-500 bg-emerald-100 text-emerald-700';
                } else {
                    badgeText = result.charAt(0).toUpperCase() + result.slice(1);
                    badgeClass = 'border-red-500 bg-red-100 text-red-700';
                }
                resultBadge.className = `inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-bold ${badgeClass}`;
                resultBadge.textContent = badgeText;
                resultCell.appendChild(resultBadge);
                tr.appendChild(resultCell);

                const flowCell = document.createElement('td');
                flowCell.className = 'py-2 text-right';
                const flowLink = document.createElement('span');
                flowLink.className = 'text-[11px] font-semibold text-sky-400 hover:text-sky-300 underline';
                flowLink.textContent = 'Open flow \u2197';
                flowCell.appendChild(flowLink);
                tr.appendChild(flowCell);

                tbody.appendChild(tr);
            });

            table.appendChild(tbody);
            scroll.appendChild(table);
            enrollmentAttemptsWrap.appendChild(scroll);
            enrollmentAttemptsWrap.classList.remove('hidden');
        }

        function setCachedConfigDownloadLinkState(isVisible, filename = '', content = '') {
            if (!cachedConfigDownloadLink) {
                return;
            }

            if (cachedConfigDownloadObjectUrl) {
                URL.revokeObjectURL(cachedConfigDownloadObjectUrl);
                cachedConfigDownloadObjectUrl = '';
            }

            if (!isVisible || !content) {
                cachedConfigDownloadLink.classList.add('hidden');
                cachedConfigDownloadLink.removeAttribute('href');
                cachedConfigDownloadLink.removeAttribute('download');
                return;
            }

            const sanitizedContent = stripSuppressedOutputLines(content);
            const blob = new Blob([sanitizedContent], { type: 'text/plain;charset=utf-8' });
            cachedConfigDownloadObjectUrl = URL.createObjectURL(blob);
            cachedConfigDownloadLink.href = cachedConfigDownloadObjectUrl;
            cachedConfigDownloadLink.download = filename || 'cached_config_output.log';
            cachedConfigDownloadLink.classList.remove('hidden');
        }

        function setTransactionDownloadLinkState(isVisible, filename = '', content = '') {
            if (!transactionDownloadLink) {
                return;
            }

            if (transactionDownloadObjectUrl) {
                URL.revokeObjectURL(transactionDownloadObjectUrl);
                transactionDownloadObjectUrl = '';
            }

            if (!isVisible || !content) {
                transactionDownloadLink.classList.add('hidden');
                transactionDownloadLink.removeAttribute('href');
                transactionDownloadLink.removeAttribute('download');
                return;
            }

            const sanitizedContent = stripSuppressedOutputLines(content);
            const blob = new Blob([sanitizedContent], { type: 'text/plain;charset=utf-8' });
            transactionDownloadObjectUrl = URL.createObjectURL(blob);
            transactionDownloadLink.href = transactionDownloadObjectUrl;
            transactionDownloadLink.download = filename || 'transaction_analysis.log';
            transactionDownloadLink.classList.remove('hidden');
        }

        function resetServerConnectivitySummary() {
            if (serverConnectivitySummaryDownloadUrls.length) {
                serverConnectivitySummaryDownloadUrls.forEach((url) => {
                    URL.revokeObjectURL(url);
                });
            }
            serverConnectivitySummaryDownloadUrls = [];

            if (serverConnectivityDiagram) {
                serverConnectivityDiagram.innerHTML = '';
            }
            if (serverConnectivityStatusChecks) {
                serverConnectivityStatusChecks.innerHTML = '';
            }
            if (serverConnectivityDownloads) {
                serverConnectivityDownloads.innerHTML = '';
            }
            if (serverConnectivityTimeRange) {
                serverConnectivityTimeRange.textContent = '';
            }
            if (serverConnectivityTotalHits) {
                serverConnectivityTotalHits.textContent = '';
            }
            if (serverConnectivitySummaryWrap) {
                serverConnectivitySummaryWrap.classList.add('hidden');
            }
        }

        function resetDuoPostureFlowSummary() {
            if (duoPostureSummaryDownloadUrls.length) {
                duoPostureSummaryDownloadUrls.forEach((url) => {
                    URL.revokeObjectURL(url);
                });
            }
            duoPostureSummaryDownloadUrls = [];

            if (duoPostureFlowSummaryBody) {
                duoPostureFlowSummaryBody.innerHTML = '';
            }
            if (duoPostureFlowFilter) {
                duoPostureFlowFilter.textContent = '';
            }
            if (duoPostureFlowTotalPatterns) {
                duoPostureFlowTotalPatterns.textContent = '';
            }
            if (duoPostureFlowTimeRange) {
                duoPostureFlowTimeRange.textContent = '';
            }
            if (duoPostureFlowSummaryWrap) {
                duoPostureFlowSummaryWrap.classList.add('hidden');
            }
        }

        function fillAiInsightList(container, values) {
            if (!container) {
                return;
            }
            container.innerHTML = '';
            const rows = Array.isArray(values) ? values : [];
            if (!rows.length) {
                const fallback = document.createElement('li');
                fallback.textContent = 'Not available';
                container.appendChild(fallback);
                return;
            }
            rows.forEach((item) => {
                const li = document.createElement('li');
                li.textContent = String(item || '').trim() || 'Not available';
                container.appendChild(li);
            });
        }

        function getFirstMeaningfulValue(values, fallbackText) {
            const rows = Array.isArray(values) ? values : [];
            for (const item of rows) {
                const line = String(item || '').trim();
                if (line) {
                    return line;
                }
            }
            return fallbackText;
        }

        function deriveAiInsightVerdict(insight) {
            const summary = String((insight && insight.executive_summary) || '').toLowerCase();
            const rootCause = String((insight && insight.root_cause_hypothesis) || '').toLowerCase();
            const evidenceText = Array.isArray(insight && insight.evidence)
                ? insight.evidence.map((item) => String(item || '').toLowerCase()).join(' ')
                : '';
            const combined = `${summary} ${rootCause} ${evidenceText}`;

            if (/(failed|failure|error|critical|blocked|timeout|unreachable)/.test(combined)) {
                return 'Verdict: Failure Indicators Detected';
            }
            if (/(success|succeeded|healthy|resolved|no issue|no issues|passed)/.test(combined)) {
                return 'Verdict: No Critical Failure Indicators';
            }
            return 'Verdict: Inconclusive';
        }

        function buildSuggestedArticleCards(insight) {
            const summary = String((insight && insight.executive_summary) || '').toLowerCase();
            const rootCause = String((insight && insight.root_cause_hypothesis) || '').toLowerCase();
            const evidenceText = Array.isArray(insight && insight.evidence)
                ? insight.evidence.map((item) => String(item || '').toLowerCase()).join(' ')
                : '';
            const combined = `${summary} ${rootCause} ${evidenceText}`;

            const suggestions = [];
            if (/(cert|certificate|trust|tls|acme)/.test(combined)) {
                suggestions.push({
                    type: 'Runbook',
                    read: '3 min',
                    title: 'Fix Certificate Trust Chain Mismatch',
                    description: 'Validate server chain, intermediate CA, endpoint trust-store, and thumbprint alignment.',
                });
            }
            if (/(enroll|enrollment|dha|bootstrap|saml)/.test(combined)) {
                suggestions.push({
                    type: 'KB',
                    read: '4 min',
                    title: 'Read Enrollment Stats Without False Positives',
                    description: 'Use overall result plus stage-level failures to classify outcome with confidence.',
                });
            }
            if (/(sync|configuration|config sync|policy)/.test(combined)) {
                suggestions.push({
                    type: 'Guide',
                    read: '5 min',
                    title: 'Configuration Sync Troubleshooting Checklist',
                    description: 'Correlate sync requests, HTTP status, retries, and next-sync intervals across logs.',
                });
            }
            if (/(network|connectivity|unreachable|timeout|srv|dns)/.test(combined)) {
                suggestions.push({
                    type: 'Guide',
                    read: '4 min',
                    title: 'Network and SRV Flow Validation Steps',
                    description: 'Verify DNS SRV records, target reachability, and timeframe-correlated flow failures.',
                });
            }

            if (!suggestions.length) {
                suggestions.push({
                    type: 'Guide',
                    read: '3 min',
                    title: 'General DartHawk Verification Checklist',
                    description: 'Run one fresh attempt, confirm timeline alignment, and validate top evidence markers.',
                });
            }

            return suggestions.slice(0, 3);
        }

        function renderAiInsightArticles(insight) {
            if (!aiInsightArticles || !aiInsightArticlesWrap) {
                return;
            }

            aiInsightArticles.innerHTML = '';
            const cards = buildSuggestedArticleCards(insight);

            cards.forEach((article) => {
                const card = document.createElement('article');
                card.className = 'rounded-lg border border-sky-500/20 bg-black/25 px-3 py-2';

                const meta = document.createElement('div');
                meta.className = 'text-[11px] text-sky-200/75';
                meta.textContent = `${article.type} | ${article.read}`;

                const title = document.createElement('div');
                title.className = 'mt-0.5 text-sm font-bold text-sky-100';
                title.textContent = article.title;

                const description = document.createElement('p');
                description.className = 'mt-0.5 text-xs text-sky-200/85 leading-relaxed';
                description.textContent = article.description;

                card.appendChild(meta);
                card.appendChild(title);
                card.appendChild(description);
                aiInsightArticles.appendChild(card);
            });

            aiInsightArticlesWrap.classList.remove('hidden');
        }

        function setAiInsightConfidenceStyle(level) {
            if (!aiInsightConfidenceBadge) {
                return;
            }

            aiInsightConfidenceBadge.classList.remove('ai-confidence-high', 'ai-confidence-medium', 'ai-confidence-low');
            if (!level) {
                return;
            }
            aiInsightConfidenceBadge.classList.add(level);
        }

        function buildAiInsightPlainText() {
            const summary = aiInsightSummary ? String(aiInsightSummary.textContent || '').trim() : '';
            const rootCause = aiInsightRootCause ? String(aiInsightRootCause.textContent || '').trim() : '';
            const verdict = aiInsightVerdict ? String(aiInsightVerdict.textContent || '').trim() : 'Verdict: Inconclusive';
            const keyEvidence = aiInsightKeyEvidence ? String(aiInsightKeyEvidence.textContent || '').trim() : 'Not available';

            const listToLines = (container) => {
                if (!container) {
                    return [];
                }
                return Array.from(container.querySelectorAll('li'))
                    .map((node) => String(node.textContent || '').trim())
                    .filter((line) => Boolean(line));
            };

            const evidenceLines = listToLines(aiInsightEvidence);
            const actionLines = listToLines(aiInsightActions);
            const gapLines = listToLines(aiInsightGaps);
            const confidence = aiInsightConfidence ? String(aiInsightConfidence.textContent || 'N/A').trim() : 'N/A';

            const lines = [
                'AI Structured Insight',
                verdict,
                `Confidence: ${confidence}`,
                `Key Evidence: ${keyEvidence}`,
                '',
                `Immediate Fix: ${summary || 'Not available'}`,
                '',
                `Why This Fix: ${rootCause || 'Not available'}`,
                '',
                'How To Validate:',
                ...(actionLines.length ? actionLines.map((line) => `- ${line}`) : ['- Not available']),
                '',
                'If It Still Fails:',
                ...(gapLines.length ? gapLines.map((line) => `- ${line}`) : ['- Not available']),
                '',
                'Evidence Lines:',
                ...(evidenceLines.length ? evidenceLines.map((line) => `- ${line}`) : ['- Not available']),
            ];

            return lines.join(String.fromCharCode(10));
        }

        function resetAiInsightCard() {
            if (!aiInsightCard) {
                return;
            }
            aiInsightCard.classList.add('hidden');
            latestAiInsightJson = null;
            setAiInsightConfidenceStyle('');
            if (aiInsightVerdict) {
                aiInsightVerdict.textContent = 'Verdict: Pending';
            }
            if (aiInsightConfidence) {
                aiInsightConfidence.textContent = 'N/A';
            }
            if (aiInsightKeyEvidence) {
                aiInsightKeyEvidence.textContent = 'Not available';
            }
            if (aiInsightSummary) {
                aiInsightSummary.textContent = '';
            }
            if (aiInsightRootCause) {
                aiInsightRootCause.textContent = '';
            }
            if (aiInsightDetails) {
                aiInsightDetails.open = false;
            }
            fillAiInsightList(aiInsightEvidence, []);
            fillAiInsightList(aiInsightActions, []);
            fillAiInsightList(aiInsightGaps, []);
            if (aiInsightArticles) {
                aiInsightArticles.innerHTML = '';
            }
            if (aiInsightArticlesWrap) {
                aiInsightArticlesWrap.classList.remove('hidden');
            }

            if (aiInsightCopyResetTimer) {
                clearTimeout(aiInsightCopyResetTimer);
                aiInsightCopyResetTimer = null;
            }
            if (aiInsightCopyBtn) {
                aiInsightCopyBtn.textContent = 'Copy AI Summary';
                aiInsightCopyBtn.disabled = false;
            }
            if (aiInsightDownloadBtn) {
                aiInsightDownloadBtn.disabled = false;
            }
        }

        function renderAiInsightCard(aiPayload) {
            if (!aiInsightCard) {
                return;
            }

            const insight = aiPayload && typeof aiPayload === 'object' ? aiPayload.analysis_json : null;
            if (!insight || typeof insight !== 'object') {
                resetAiInsightCard();
                return;
            }

            latestAiInsightJson = insight;

            const confidenceValue = Number(insight.confidence_score);
            const confidenceText = Number.isFinite(confidenceValue)
                ? `${Math.max(0, Math.min(100, Math.round(confidenceValue)))}/100`
                : 'N/A';

            if (Number.isFinite(confidenceValue)) {
                const normalizedScore = Math.max(0, Math.min(100, Math.round(confidenceValue)));
                if (normalizedScore >= 75) {
                    setAiInsightConfidenceStyle('ai-confidence-high');
                } else if (normalizedScore >= 50) {
                    setAiInsightConfidenceStyle('ai-confidence-medium');
                } else {
                    setAiInsightConfidenceStyle('ai-confidence-low');
                }
            } else {
                setAiInsightConfidenceStyle('');
            }

            if (aiInsightConfidence) {
                aiInsightConfidence.textContent = confidenceText;
            }
            if (aiInsightVerdict) {
                aiInsightVerdict.textContent = deriveAiInsightVerdict(insight);
            }
            if (aiInsightSummary) {
                aiInsightSummary.textContent = String(insight.executive_summary || 'Not available').trim() || 'Not available';
            }
            if (aiInsightRootCause) {
                aiInsightRootCause.textContent = String(insight.root_cause_hypothesis || 'Not available').trim() || 'Not available';
            }

            if (aiInsightKeyEvidence) {
                aiInsightKeyEvidence.textContent = getFirstMeaningfulValue(insight.evidence, 'Not available');
            }

            fillAiInsightList(aiInsightEvidence, insight.evidence);
            fillAiInsightList(aiInsightActions, insight.immediate_next_actions);
            fillAiInsightList(aiInsightGaps, insight.data_gaps);
            renderAiInsightArticles(insight);

            aiInsightCard.classList.remove('hidden');
        }

        function setAgentChatStatus(text) {
            if (!agentChatStatus) {
                return;
            }
            agentChatStatus.textContent = String(text || '').trim() || 'Ready';
        }

        function setAgentChatBusy(isBusy) {
            if (agentChatInput) {
                agentChatInput.disabled = Boolean(isBusy);
            }
            if (agentChatSendBtn) {
                agentChatSendBtn.disabled = Boolean(isBusy);
                agentChatSendBtn.textContent = isBusy ? 'Thinking...' : 'Ask Agent';
            }
        }

        function appendAgentChatMessage(role, text) {
            if (!agentChatMessages) {
                return;
            }

            const messageWrap = document.createElement('div');
            messageWrap.className = role === 'user'
                ? 'rounded-lg border border-sky-500/30 bg-sky-500/5 px-3 py-2'
                : 'rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-3 py-2';

            const roleLabel = document.createElement('div');
            roleLabel.className = 'text-xs font-bold tracking-wider uppercase mb-1';
            roleLabel.textContent = role === 'user' ? 'You' : 'Agent';

            const body = document.createElement('div');
            body.className = 'text-sm whitespace-pre-wrap';
            body.textContent = String(text || '').trim() || '(no content)';

            messageWrap.appendChild(roleLabel);
            messageWrap.appendChild(body);
            agentChatMessages.appendChild(messageWrap);
            agentChatMessages.scrollTop = agentChatMessages.scrollHeight;
        }

        function resetAgentChatCard() {
            currentAnalysisSessionId = '';
            agentChatHistory = [];

            if (agentChatMessages) {
                agentChatMessages.innerHTML = '';
            }

            if (agentChatInput) {
                agentChatInput.value = '';
            }

            setAgentChatBusy(false);
            setAgentChatStatus('Session not ready');

            if (agentChatCard) {
                agentChatCard.classList.add('hidden');
            }
        }

        function setInsightText(node, value, fallback = 'Not found') {
            if (!node) {
                return;
            }
            const text = String(value || '').trim();
            node.textContent = text || fallback;
        }

        // Translate a raw agent log line into a plain-English description so
        // the snapshot stays readable; the raw line is still available on demand.
        const EVIDENCE_DESCRIPTORS = [
            { re: /CIpcPipesConnection|\\pipe\\com\.cisco\.secureclient|AsyncSendPayload/i, icon: '\uD83D\uDD0C', text: 'Local IPC channel to the ZTA service' },
            { re: /closeStatus\s*=\s*RequestTimedOut/i, icon: '\u23F1\uFE0F', text: 'Connection closed after the request timed out' },
            { re: /DnsFlowHandler::handleRequestTimeout/i, icon: '\u23F1\uFE0F', text: 'DNS request timed out' },
            { re: /DnsFlowHandler::handleClose/i, icon: '\u23F1\uFE0F', text: 'DNS flow closed on a request timeout' },
            { re: /DohClient|OnDohRequestComplete|dns-query/i, icon: '\uD83C\uDF10', text: 'DNS-over-HTTPS query to Secure Access' },
            { re: /OnNetworkChange/i, icon: '\uD83D\uDD04', text: 'Network change detected (Wi-Fi / adapter change)' },
            { re: /debounce timer|handleDebounceTimerExpired/i, icon: '\uD83D\uDD04', text: 'Reconnect debounce fired after a network change' },
            { re: /onResponseHeadersReceived/i, icon: '\uD83C\uDF10', text: 'HTTP/2 response received from the headend' },
            { re: /tunnel cannot receive/i, icon: '\uD83D\uDEA7', text: 'Transport tunnel not ready to receive data' },
            { re: /Http2MuxTransport/i, icon: '\uD83D\uDEA7', text: 'HTTP/2 transport activity' },
            { re: /captive.?portal/i, icon: '\uD83D\uDCF6', text: 'Captive-portal / reachability check' },
            { re: /handshake|certificate|\btls\b/i, icon: '\uD83D\uDD12', text: 'TLS handshake / certificate activity' },
            { re: /posture|DhaPostureClient|\bDHA\b/i, icon: '\uD83D\uDEE1\uFE0F', text: 'Device posture (DHA) activity' },
            { re: /\btunnel\b/i, icon: '\uD83D\uDEA7', text: 'Tunnel transport activity' },
            { re: /enroll/i, icon: '\uD83D\uDCDD', text: 'Enrollment activity' },
        ];
        function describeEvidenceLine(raw) {
            const s = String(raw || '').trim();
            for (let i = 0; i < EVIDENCE_DESCRIPTORS.length; i += 1) {
                if (EVIDENCE_DESCRIPTORS[i].re.test(s)) {
                    return { icon: EVIDENCE_DESCRIPTORS[i].icon, text: EVIDENCE_DESCRIPTORS[i].text };
                }
            }
            // Fallback: humanize the Class::method() into a readable phrase so
            // distinct log lines get distinct, non-cryptic labels.
            const cleaned = s
                .replace(/^.*?\bcsc_zta_agent\b(?:\[[^\]]*\])?\s*:?\s*/i, '')
                .replace(/^\[[^\]]*\]\s*/i, '')
                .replace(/^[A-Za-z]\/\s*/, '')
                .replace(/^[<>-]+\s*/, '')
                .replace(/\b[\w./-]+\.(?:cpp|cc|cxx|c|hpp|h|py|go|rs|js|mm):\d+\s*/i, '')
                .replace(/<hex>|<ip>|<id>/g, '')
                .replace(/\b[0-9a-fA-F]{6,}\b/g, '')
                .replace(/\s*[:=]\s*N\b/g, '')
                .replace(/\s+N\b\s*$/i, '')
                .replace(/\s+/g, ' ')
                .replace(/[\s:=,-]+$/, '')
                .trim();
            const method = cleaned.match(/([A-Za-z0-9_]+)::([A-Za-z0-9_]+)\s*\(\)/)
                || cleaned.match(/\b([A-Za-z0-9_]+)\s*\(\)/);
            if (method) {
                const name = method[2] || method[1];
                const words = name
                    .replace(/_/g, ' ')
                    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
                    .toLowerCase()
                    .trim();
                const phrase = words.charAt(0).toUpperCase() + words.slice(1);
                return { icon: '\u2139\uFE0F', text: phrase };
            }
            const short = cleaned.length > 90 ? cleaned.slice(0, 90).trim() + '\u2026' : cleaned;
            const label = short ? short.charAt(0).toUpperCase() + short.slice(1) : 'Agent activity';
            return { icon: '\u2139\uFE0F', text: label };
        }

        let lastZtaPreviewSignals = null;

        // The upload preview is ZTA-shaped, so it is only shown for modules it describes.
        function syncZtaSummaryForModule() {
            const selected = document.querySelector('input[name="module"]:checked');
            const isUztna = selected && selected.value === 'UZTNA';
            if (isUztna || !lastZtaPreviewSignals || !lastZtaPreviewSignals.available) {
                resetZtaSummary();
                return;
            }
            renderZtaSummary(lastZtaPreviewSignals);
        }

        function resetZtaSummary() {
            if (ztaSummaryHeadline) {
                ztaSummaryHeadline.textContent = '';
            }
            if (ztaSummaryVerdict) {
                ztaSummaryVerdict.textContent = '';
                ztaSummaryVerdict.className = 'hidden mt-3 rounded-lg border p-3';
            }
            if (ztaSummaryTiles) {
                ztaSummaryTiles.innerHTML = '';
            }
            const statsHost = document.getElementById('ztaSummaryStats');
            if (statsHost) {
                statsHost.innerHTML = '';
                statsHost.classList.add('hidden');
            }
            const nextHost = document.getElementById('ztaSummaryNext');
            if (nextHost) {
                nextHost.innerHTML = '';
                nextHost.classList.add('hidden');
            }
            if (ztaSummaryPanel) {
                ztaSummaryPanel.classList.add('hidden');
            }
        }

        function renderZtaSummary(signals) {
            resetZtaSummary();
            if (!ztaSummaryPanel || !ztaSummaryTiles) {
                return;
            }
            if (!signals || typeof signals !== 'object' || !signals.available) {
                return;
            }

            const num = (value) => (Number.isFinite(Number(value)) ? Number(value) : 0);
            const appendTextWithLinks = (parent, text) => {
                const urlPattern = /(https?:\/\/[^\s]+)/g;
                let lastIndex = 0;
                let match;
                while ((match = urlPattern.exec(text)) !== null) {
                    if (match.index > lastIndex) {
                        parent.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
                    }
                    const anchor = document.createElement('a');
                    anchor.href = match[0];
                    anchor.target = '_blank';
                    anchor.rel = 'noopener noreferrer';
                    anchor.className = 'dh-suggest-link';
                    anchor.textContent = match[0];
                    parent.appendChild(anchor);
                    lastIndex = match.index + match[0].length;
                }
                if (lastIndex < text.length) {
                    parent.appendChild(document.createTextNode(text.slice(lastIndex)));
                }
            };
            const assessment = Array.isArray(signals.assessment) ? signals.assessment : [];
            if (!assessment.length) {
                return;
            }

            const RANK = { critical: 3, warning: 2, info: 1, ok: 0 };
            const rankOf = (sev) => (sev in RANK ? RANK[sev] : 1);
            const SEV_LABEL = { critical: 'Critical', warning: 'Warning', info: 'Info', ok: 'OK' };
            const SEV_GLYPH = { critical: '\u2715', warning: '\u26a0', info: '\u25cf', ok: '\u2713' };

            const issues = assessment
                .filter((card) => card.severity === 'critical' || card.severity === 'warning')
                .sort((a, b) => rankOf(b.severity) - rankOf(a.severity));
            const healthy = assessment.filter((card) => card.severity === 'info' || card.severity === 'ok');

            // --- Overall verdict banner (clean, theme-aware) ---
            const verdict = signals.verdict && typeof signals.verdict === 'object' ? signals.verdict : {};
            const verdictLevel = ['healthy', 'degraded', 'problem'].includes(String(verdict.level))
                ? String(verdict.level) : 'healthy';
            const verdictTitle = { healthy: 'Healthy', degraded: 'Degraded', problem: 'Problem detected' }[verdictLevel];
            const verdictGlyph = { healthy: '\u2713', degraded: '\u26a0', problem: '\u2715' }[verdictLevel];

            if (ztaSummaryVerdict) {
                ztaSummaryVerdict.className = `dh-snap-verdict is-${verdictLevel}`;
                const vTitle = document.createElement('div');
                vTitle.className = 'dh-snap-verdict-title';
                vTitle.textContent = `${verdictGlyph} ${verdictTitle}`;
                ztaSummaryVerdict.appendChild(vTitle);
                if (verdict.summary) {
                    const vSummary = document.createElement('div');
                    vSummary.className = 'dh-snap-verdict-summary';
                    vSummary.textContent = String(verdict.summary);
                    ztaSummaryVerdict.appendChild(vSummary);
                }
            }

            // Headline pill (top-right of panel).
            const criticalCount = issues.filter((c) => c.severity === 'critical').length;
            const warningCount = issues.filter((c) => c.severity === 'warning').length;
            if (ztaSummaryHeadline) {
                if (criticalCount > 0) {
                    ztaSummaryHeadline.textContent = `\u2715 ${criticalCount} critical`;
                    ztaSummaryHeadline.className = 'text-sm font-semibold text-rose-300';
                } else if (warningCount > 0) {
                    ztaSummaryHeadline.textContent = `\u26a0 ${warningCount} to review`;
                    ztaSummaryHeadline.className = 'text-sm font-semibold text-amber-300';
                } else {
                    ztaSummaryHeadline.textContent = '\u2713 All clear';
                    ztaSummaryHeadline.className = 'text-sm font-semibold text-emerald-300';
                }
            }

            if (ztaSummaryHint) {
                ztaSummaryHint.textContent = issues.length
                    ? 'Problems needing attention are shown first, with suggested next steps. Healthy checks are summarized below.'
                    : 'All ZTA health checks passed.';
            }

            // --- Summary tiles + severity donut (real data from the assessment) ---
            const statsHost = document.getElementById('ztaSummaryStats');
            if (statsHost) {
                statsHost.innerHTML = '';
                const healthScore = Math.max(0, Math.min(100, 100 - (criticalCount * 25) - (warningCount * 10)));
                const flowsCard = assessment.find((c) => c.label === 'Flows');
                let flowCount = 0;
                let flowSub = '';
                if (flowsCard) {
                    const m = String(flowsCard.chip || '').match(/\d[\d,]*/);
                    flowCount = m ? Number(m[0].replace(/,/g, '')) : 0;
                    const groups = Array.isArray(flowsCard.groups) ? flowsCard.groups : [];
                    flowSub = groups.length ? `${groups.length} destination${groups.length === 1 ? '' : 's'}` : (flowsCard.metric || '');
                }
                const scoreClass = healthScore >= 85 ? 'is-good' : (healthScore >= 60 ? 'is-warn' : 'is-bad');

                const stats = document.createElement('div');
                stats.className = 'dh-snap-stats';

                const tiles = document.createElement('div');
                tiles.className = 'dh-snap-tiles';
                const mkTile = (label, value, sub, cls) => {
                    const t = document.createElement('div');
                    t.className = `dh-snap-tile${cls ? ' ' + cls : ''}`;
                    const l = document.createElement('div'); l.className = 'dh-snap-tile-label'; l.textContent = label;
                    const v = document.createElement('div'); v.className = 'dh-snap-tile-value'; v.textContent = value;
                    t.appendChild(l); t.appendChild(v);
                    if (sub) { const s = document.createElement('div'); s.className = 'dh-snap-tile-sub'; s.textContent = sub; t.appendChild(s); }
                    return t;
                };
                tiles.appendChild(mkTile('Health score', String(healthScore), 'out of 100', scoreClass));
                tiles.appendChild(mkTile('Needs attention', String(issues.length), issues.length ? 'warnings / critical' : 'none', issues.length ? (criticalCount ? 'is-bad' : 'is-warn') : 'is-good'));
                tiles.appendChild(mkTile('Healthy checks', String(healthy.length), `of ${assessment.length} total`, 'is-good'));
                tiles.appendChild(mkTile('Flows analyzed', String(flowCount), flowSub, ''));
                stats.appendChild(tiles);

                // Donut by severity status.
                const segs = [
                    { key: 'critical', color: '#ef4444', n: criticalCount, label: 'Critical' },
                    { key: 'warning', color: '#f59e0b', n: warningCount, label: 'Warning' },
                    { key: 'healthy', color: '#10b981', n: healthy.length, label: 'Healthy' },
                ].filter((s) => s.n > 0);
                const total = segs.reduce((acc, s) => acc + s.n, 0) || 1;
                const donut = document.createElement('div');
                donut.className = 'dh-snap-donut';
                const NS = 'http://www.w3.org/2000/svg';
                const svg = document.createElementNS(NS, 'svg');
                svg.setAttribute('viewBox', '0 0 42 42');
                svg.setAttribute('width', '96'); svg.setAttribute('height', '96');
                const r = 15.915; const cx = 21; const cy = 21;
                const track = document.createElementNS(NS, 'circle');
                track.setAttribute('cx', cx); track.setAttribute('cy', cy); track.setAttribute('r', r);
                track.setAttribute('fill', 'transparent'); track.setAttribute('stroke', 'var(--border-main)'); track.setAttribute('stroke-width', '5');
                svg.appendChild(track);
                let offset = 25; // start at top
                segs.forEach((s) => {
                    const pct = (s.n / total) * 100;
                    const c = document.createElementNS(NS, 'circle');
                    c.setAttribute('cx', cx); c.setAttribute('cy', cy); c.setAttribute('r', r);
                    c.setAttribute('fill', 'transparent'); c.setAttribute('stroke', s.color); c.setAttribute('stroke-width', '5');
                    c.setAttribute('stroke-dasharray', `${pct} ${100 - pct}`);
                    c.setAttribute('stroke-dashoffset', String(offset));
                    svg.appendChild(c);
                    offset = (offset - pct + 100) % 100;
                });
                const center = document.createElementNS(NS, 'text');
                center.setAttribute('x', cx); center.setAttribute('y', cy + 1);
                center.setAttribute('text-anchor', 'middle'); center.setAttribute('dominant-baseline', 'middle');
                center.setAttribute('font-size', '9'); center.setAttribute('font-weight', '800'); center.setAttribute('fill', 'var(--text-main)');
                center.textContent = String(assessment.length);
                svg.appendChild(center);
                donut.appendChild(svg);
                const legend = document.createElement('div');
                legend.className = 'dh-snap-donut-legend';
                (segs.length ? segs : [{ color: '#10b981', n: healthy.length, label: 'Healthy' }]).forEach((s) => {
                    const row = document.createElement('div'); row.className = 'row';
                    const dot = document.createElement('span'); dot.className = 'dot'; dot.style.background = s.color;
                    const txt = document.createElement('span');
                    const n = document.createElement('span'); n.className = 'n'; n.textContent = String(s.n);
                    txt.appendChild(n); txt.appendChild(document.createTextNode(` ${s.label}`));
                    row.appendChild(dot); row.appendChild(txt); legend.appendChild(row);
                });
                donut.appendChild(legend);
                stats.appendChild(donut);

                statsHost.appendChild(stats);
                statsHost.classList.remove('hidden');
            }

            // Container becomes a vertical stack (not a grid).
            ztaSummaryTiles.className = 'mt-4 flex flex-col';

            // --- Top destinations (which destinations flows were steered to) ---
            (() => {
                const flowsCard = assessment.find((c) => c.label === 'Flows');
                const destGroups = flowsCard && flowsCard.group_kind === 'destination' && Array.isArray(flowsCard.groups)
                    ? flowsCard.groups.filter((g) => g && String(g.label || '').trim()) : [];
                if (!destGroups.length) { return; }
                const sorted = destGroups.slice().sort((a, b) => num(b.count) - num(a.count));
                const maxCount = Math.max(1, ...sorted.map((g) => num(g.count)));
                const totalCount = sorted.reduce((s, g) => s + num(g.count), 0) || 1;
                const palette = ['#6366f1', '#0ea5e9', '#10b981', '#f59e0b', '#ef4444', '#a855f7'];

                const panel = document.createElement('div');
                panel.className = 'dh-dest-panel';

                const head = document.createElement('div');
                head.className = 'dh-dest-head';
                const htitle = document.createElement('span');
                htitle.className = 'dh-dest-title';
                htitle.textContent = 'Top destinations';
                const hsub = document.createElement('span');
                hsub.className = 'dh-dest-sub';
                hsub.textContent = `${totalCount} flow${totalCount === 1 ? '' : 's'} across ${sorted.length} destination${sorted.length === 1 ? '' : 's'}`;
                head.appendChild(htitle);
                head.appendChild(hsub);
                panel.appendChild(head);

                const body = document.createElement('div');
                body.className = 'dh-dest-body';

                // Donut of destination share.
                const NS = 'http://www.w3.org/2000/svg';
                const donutWrap = document.createElement('div');
                donutWrap.className = 'dh-dest-donut';
                const svg = document.createElementNS(NS, 'svg');
                svg.setAttribute('viewBox', '0 0 42 42');
                svg.setAttribute('width', '84'); svg.setAttribute('height', '84');
                const r = 15.915; const cx = 21; const cy = 21;
                const track = document.createElementNS(NS, 'circle');
                track.setAttribute('cx', cx); track.setAttribute('cy', cy); track.setAttribute('r', r);
                track.setAttribute('fill', 'transparent'); track.setAttribute('stroke', 'var(--border-main)'); track.setAttribute('stroke-width', '5');
                svg.appendChild(track);
                let dOffset = 25;
                sorted.forEach((g, i) => {
                    const pct = (num(g.count) / totalCount) * 100;
                    const c = document.createElementNS(NS, 'circle');
                    c.setAttribute('cx', cx); c.setAttribute('cy', cy); c.setAttribute('r', r);
                    c.setAttribute('fill', 'transparent');
                    c.setAttribute('stroke', palette[i % palette.length]);
                    c.setAttribute('stroke-width', '5');
                    c.setAttribute('stroke-dasharray', `${pct} ${100 - pct}`);
                    c.setAttribute('stroke-dashoffset', String(dOffset));
                    const t = document.createElementNS(NS, 'title');
                    t.textContent = `${g.label} \u2014 ${num(g.count)} (${Math.round(pct)}%)`;
                    c.appendChild(t);
                    svg.appendChild(c);
                    dOffset = (dOffset - pct + 100) % 100;
                });
                donutWrap.appendChild(svg);
                body.appendChild(donutWrap);

                // Ranked destination bars (verbatim destination labels).
                const bars = document.createElement('div');
                bars.className = 'dh-dest-bars';
                sorted.forEach((g, i) => {
                    const n = num(g.count);
                    const row = document.createElement('div');
                    row.className = 'dh-evrow';
                    const main = document.createElement('div');
                    main.className = 'dh-evrow-main';
                    const dot = document.createElement('span');
                    dot.className = 'dh-evrow-icon dh-dest-dot';
                    dot.style.background = palette[i % palette.length];
                    const text = document.createElement('div');
                    text.className = 'dh-evrow-text dh-dest-name';
                    text.textContent = String(g.label);
                    text.title = String(g.label);
                    const count = document.createElement('span');
                    count.className = 'dh-evrow-count';
                    count.textContent = `${n}\u00d7`;
                    count.title = `${n} flow${n === 1 ? '' : 's'}`;
                    main.appendChild(dot);
                    main.appendChild(text);
                    main.appendChild(count);
                    const meter = document.createElement('div');
                    meter.className = 'dh-evrow-meter';
                    const fill = document.createElement('div');
                    fill.className = 'dh-evrow-meter-fill';
                    fill.style.width = `${Math.max(4, Math.round((n / maxCount) * 100))}%`;
                    fill.style.background = palette[i % palette.length];
                    fill.style.opacity = '0.85';
                    const pct = Math.round((n / totalCount) * 100);
                    meter.title = `${n} of ${totalCount} flows (${pct}%)`;
                    meter.appendChild(fill);
                    row.appendChild(main);
                    row.appendChild(meter);
                    bars.appendChild(row);
                });
                body.appendChild(bars);

                panel.appendChild(body);
                ztaSummaryTiles.appendChild(panel);
            })();

            // --- Issues (expanded inline, no clicking needed) ---
            if (issues.length) {
                const section = document.createElement('div');
                section.className = 'dh-snap-section';
                section.textContent = `Needs attention (${issues.length})`;
                ztaSummaryTiles.appendChild(section);

                issues.forEach((card) => {
                    const sev = card.severity === 'critical' ? 'critical' : 'warning';
                    const groups = Array.isArray(card.groups) ? card.groups : [];
                    const suggestions = Array.isArray(card.suggestions)
                        ? card.suggestions.filter((item) => (item && typeof item === 'object' && item.heading) || String(item || '').trim()) : [];

                    const el = document.createElement('div');
                    el.className = `dh-issue sev-${sev}`;

                    const head = document.createElement('div');
                    head.className = 'dh-issue-head';
                    const title = document.createElement('div');
                    title.className = 'dh-issue-title';
                    title.textContent = card.label || '';
                    const badge = document.createElement('span');
                    badge.className = `dh-issue-badge sev-${sev}`;
                    badge.textContent = `${SEV_GLYPH[sev]} ${card.chip || SEV_LABEL[sev]}`;
                    head.appendChild(title);
                    head.appendChild(badge);
                    el.appendChild(head);

                    if (card.summary) {
                        const summary = document.createElement('div');
                        summary.className = 'dh-issue-summary';
                        summary.textContent = card.summary;
                        el.appendChild(summary);
                    }

                    const addBlock = (heading, text) => {
                        if (!text) { return; }
                        const block = document.createElement('div');
                        block.className = 'dh-issue-block';
                        const label = document.createElement('div');
                        label.className = 'dh-issue-block-label';
                        label.textContent = heading;
                        const body = document.createElement('div');
                        body.className = 'dh-issue-block-body';
                        body.textContent = text;
                        block.appendChild(label);
                        block.appendChild(body);
                        el.appendChild(block);
                    };
                    addBlock('What it means', card.meaning);
                    addBlock('Impact', card.impact);

                    // Cause -> effect diagram (e.g. what drove connectivity events).
                    const diagram = card.diagram && typeof card.diagram === 'object' ? card.diagram : null;
                    const diagramCauses = diagram && Array.isArray(diagram.causes)
                        ? diagram.causes.filter((c) => c && Number(c.count) > 0) : [];
                    if (diagramCauses.length) {
                        const block = document.createElement('div');
                        block.className = 'dh-issue-block';
                        const label = document.createElement('div');
                        label.className = 'dh-issue-block-label';
                        label.textContent = 'What caused it';
                        block.appendChild(label);

                        const dia = document.createElement('div');
                        dia.className = 'dh-diagram';

                        const source = document.createElement('div');
                        source.className = 'dh-diagram-node is-source';
                        source.textContent = diagram.source || 'Client';
                        dia.appendChild(source);

                        const arrowIn = document.createElement('div');
                        arrowIn.className = 'dh-diagram-arrow';
                        arrowIn.textContent = '\u2192';
                        dia.appendChild(arrowIn);

                        const causesCol = document.createElement('div');
                        causesCol.className = 'dh-diagram-causes';
                        diagramCauses.forEach((c) => {
                            const cause = document.createElement('div');
                            cause.className = 'dh-diagram-cause';
                            const count = document.createElement('span');
                            count.className = 'dh-diagram-cause-count';
                            count.textContent = `${num(c.count)}\u00d7`;
                            const txt = document.createElement('span');
                            txt.className = 'dh-diagram-cause-text';
                            txt.textContent = String(c.label || '');
                            if (c.hint) { cause.title = String(c.hint); }
                            cause.appendChild(count);
                            cause.appendChild(txt);
                            causesCol.appendChild(cause);
                        });
                        dia.appendChild(causesCol);

                        const arrowOut = document.createElement('div');
                        arrowOut.className = 'dh-diagram-arrow';
                        arrowOut.textContent = '\u2192';
                        dia.appendChild(arrowOut);

                        const target = document.createElement('div');
                        target.className = 'dh-diagram-node is-target';
                        target.textContent = diagram.target || 'Server';
                        dia.appendChild(target);

                        block.appendChild(dia);
                        el.appendChild(block);
                    }

                    // Suggested next steps (always visible on issues).
                    if (suggestions.length) {
                        const box = document.createElement('div');
                        box.className = 'dh-suggest';
                        const label = document.createElement('div');
                        label.className = 'dh-suggest-label';
                        label.textContent = '\uD83D\uDCA1 Suggested next steps';
                        box.appendChild(label);
                        let list = null;
                        const ensureList = () => {
                            if (!list) {
                                list = document.createElement('ul');
                                box.appendChild(list);
                            }
                            return list;
                        };
                        suggestions.forEach((item) => {
                            if (item && typeof item === 'object' && item.heading) {
                                const subhead = document.createElement('div');
                                subhead.className = 'dh-suggest-subhead';
                                subhead.textContent = String(item.heading);
                                box.appendChild(subhead);
                                list = null;
                                return;
                            }
                            const li = document.createElement('li');
                            appendTextWithLinks(li, String(item));
                            ensureList().appendChild(li);
                        });
                        el.appendChild(box);
                    }

                    // Evidence rendered as plain-English rows describing what
                    // was logged (no raw developer log lines).
                    if (groups.length) {
                        const isDestinationKind = card.group_kind === 'destination';
                        const typeWord = isDestinationKind
                            ? (groups.length === 1 ? 'destination' : 'destinations')
                            : (groups.length === 1 ? 'event type' : 'event types');
                        const toggle = document.createElement('button');
                        toggle.type = 'button';
                        toggle.className = 'dh-evidence-toggle';
                        toggle.setAttribute('aria-expanded', 'false');
                        const setToggleLabel = (open) => {
                            toggle.textContent = isDestinationKind
                                ? `${open ? '\u25be Hide' : '\u25b8 Show'} top destinations (${groups.length})`
                                : `${open ? '\u25be Hide' : '\u25b8 Show'} what was logged (${groups.length} ${typeWord})`;
                        };
                        setToggleLabel(false);
                        const list = document.createElement('div');
                        list.className = 'dh-evlist';
                        list.style.display = 'none';
                        const sortedGroups = groups.slice().sort((a, b) => num(b.count) - num(a.count));
                        const maxCount = Math.max(1, ...sortedGroups.map((g) => num(g.count)));
                        const totalCount = sortedGroups.reduce((sum, g) => sum + num(g.count), 0);
                        sortedGroups.forEach((group) => {
                            const rawLabel = String(group.label || '');
                            // Destination labels are hostnames - show them
                            // verbatim; the log-line describer would mangle them.
                            const desc = isDestinationKind
                                ? { icon: '\uD83C\uDF10', text: rawLabel }
                                : describeEvidenceLine(rawLabel);
                            const n = num(group.count);
                            const row = document.createElement('div');
                            row.className = 'dh-evrow';

                            const main = document.createElement('div');
                            main.className = 'dh-evrow-main';
                            const icon = document.createElement('span');
                            icon.className = 'dh-evrow-icon';
                            icon.textContent = desc.icon;
                            const text = document.createElement('div');
                            text.className = 'dh-evrow-text';
                            text.textContent = desc.text;
                            const count = document.createElement('span');
                            count.className = 'dh-evrow-count';
                            count.textContent = `${n}\u00d7`;
                            count.title = `${n} ${n === 1 ? 'occurrence' : 'occurrences'}`;
                            main.appendChild(icon);
                            main.appendChild(text);
                            main.appendChild(count);

                            const meter = document.createElement('div');
                            meter.className = 'dh-evrow-meter';
                            const fill = document.createElement('div');
                            fill.className = 'dh-evrow-meter-fill';
                            fill.style.width = `${Math.max(4, Math.round((n / maxCount) * 100))}%`;
                            const pct = totalCount ? Math.round((n / totalCount) * 100) : 0;
                            meter.title = `${n} of ${totalCount} events (${pct}%)`;
                            meter.appendChild(fill);

                            row.appendChild(main);
                            row.appendChild(meter);
                            list.appendChild(row);
                        });
                        toggle.addEventListener('click', () => {
                            const open = list.style.display !== 'none';
                            list.style.display = open ? 'none' : 'flex';
                            toggle.setAttribute('aria-expanded', String(!open));
                            setToggleLabel(!open);
                        });
                        el.appendChild(toggle);
                        el.appendChild(list);
                    }

                    ztaSummaryTiles.appendChild(el);
                });
            }

            // --- Healthy checks folded into one compact "all clear" row ---
            if (healthy.length) {
                if (issues.length) {
                    const section = document.createElement('div');
                    section.className = 'dh-snap-section';
                    section.textContent = 'Healthy';
                    ztaSummaryTiles.appendChild(section);
                }

                const box = document.createElement('div');
                box.className = 'dh-allclear';
                const head = document.createElement('div');
                head.className = 'dh-allclear-head';
                const title = document.createElement('span');
                title.className = 'dh-allclear-title';
                title.textContent = `\u2713 ${healthy.length} check${healthy.length === 1 ? '' : 's'} healthy`;
                head.appendChild(title);
                healthy.forEach((card) => {
                    const chip = document.createElement('span');
                    chip.className = `dh-chip${card.severity === 'info' ? ' is-info' : ''}`;
                    const dot = document.createElement('span');
                    dot.className = 'dot';
                    chip.appendChild(dot);
                    chip.appendChild(document.createTextNode(card.label || ''));
                    head.appendChild(chip);
                });

                const details = document.createElement('div');
                details.className = 'dh-allclear-details';
                healthy.forEach((card) => {
                    if (!card.summary) { return; }
                    const row = document.createElement('div');
                    row.className = 'dh-allclear-detail';
                    const strong = document.createElement('strong');
                    strong.textContent = `${card.label}: `;
                    row.appendChild(strong);
                    row.appendChild(document.createTextNode(card.summary));
                    details.appendChild(row);
                });

                if (details.childNodes.length) {
                    const toggle = document.createElement('button');
                    toggle.type = 'button';
                    toggle.className = 'dh-allclear-toggle';
                    toggle.textContent = 'Details';
                    toggle.addEventListener('click', () => {
                        const open = details.classList.toggle('open');
                        toggle.textContent = open ? 'Hide' : 'Details';
                    });
                    head.appendChild(toggle);
                }

                box.appendChild(head);
                if (details.childNodes.length) {
                    box.appendChild(details);
                }
                ztaSummaryTiles.appendChild(box);
            }

            // Global "what next" guidance so the reader knows how to go
            // deeper after skimming the snapshot.
            const nextHost = document.getElementById('ztaSummaryNext');
            if (nextHost) {
                nextHost.innerHTML = '';
                const banner = document.createElement('div');
                banner.className = 'dh-nextstep';
                const icon = document.createElement('div');
                icon.className = 'dh-nextstep-icon';
                icon.textContent = '\u2192';
                const body = document.createElement('div');
                body.className = 'dh-nextstep-body';
                const title = document.createElement('div');
                title.className = 'dh-nextstep-title';
                title.textContent = 'What next?';
                const text = document.createElement('div');
                text.className = 'dh-nextstep-text';
                text.textContent = issues.length
                    ? 'This snapshot is a quick read of the bundle. To investigate the flagged areas in depth \u2014 flows, enrollment, interception (SPA / SIA) and more \u2014 run the full ZTA analysis.'
                    : 'Everything looks healthy at a glance. To confirm with a full pass \u2014 flows, enrollment, interception (SPA / SIA) and more \u2014 run the detailed ZTA analysis.';
                const action = document.createElement('button');
                action.type = 'button';
                action.className = 'dh-nextstep-btn';
                action.textContent = 'Run detailed ZTA analysis';
                action.addEventListener('click', () => {
                    const ztaRadio = document.getElementById('mod-zta');
                    if (ztaRadio && !ztaRadio.checked) {
                        ztaRadio.checked = true;
                        ztaRadio.dataset.wasChecked = 'true';
                    }
                    try { toggleZtaOptions(); } catch (e) { /* no-op */ }
                    try { updateResultPaneForOptionInteraction(false); } catch (e) { /* no-op */ }
                    const opts = document.getElementById('ztaOptions');
                    if (opts) {
                        opts.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }
                });
                body.appendChild(title);
                body.appendChild(text);
                body.appendChild(action);
                banner.appendChild(icon);
                banner.appendChild(body);
                nextHost.appendChild(banner);
                nextHost.classList.remove('hidden');
            }

            ztaSummaryPanel.classList.remove('hidden');

            try {
                if (typeof window.dhRecordHistory === 'function') {
                    const scoreForHist = Math.max(0, Math.min(100, 100 - (criticalCount * 25) - (warningCount * 10)));
                    window.dhRecordHistory({
                        verdictLevel: verdictLevel,
                        criticalCount: criticalCount,
                        warningCount: warningCount,
                        healthyCount: healthy.length,
                        total: assessment.length,
                        healthScore: scoreForHist,
                    });
                }
            } catch (e) { /* history is non-critical */ }
        }

        function resetBundleInsightPanel() {
            if (bundleInsightPanel) {
                bundleInsightPanel.classList.add('hidden');
            }
            if (openAgentChatBtn) {
                openAgentChatBtn.classList.add('hidden');
            }
            if (bundleInsightMethodsBody) {
                bundleInsightMethodsBody.innerHTML = '';
            }
            if (bundleInsightHealthBody) {
                bundleInsightHealthBody.innerHTML = '';
            }
        }

        function renderBundleInsightPanel(previewData, selectedFileName) {
            if (!bundleInsightPanel) {
                return;
            }

            const data = previewData && typeof previewData === 'object' ? previewData : {};
            const enrollmentPreview = data.enrollment_log_preview && typeof data.enrollment_log_preview === 'object'
                ? data.enrollment_log_preview
                : {};

            setInsightText(bundleInsightOs, data.operating_system);
            setInsightText(bundleInsightClientVersion, data.cisco_secure_client_version || data.zta_version || data.vpn_version);
            setInsightText(bundleInsightOrgIds, Array.isArray(data.org_ids) && data.org_ids.length ? data.org_ids.join(', ') : 'Not found');
            setInsightText(bundleInsightEnrollmentMethod, Array.isArray(data.enrollment_methods) && data.enrollment_methods.length ? data.enrollment_methods.join(', ') : 'Not found');
            setInsightText(bundleInsightTrace, typeof data.zta_trace_level_logging_enabled === 'boolean' ? (data.zta_trace_level_logging_enabled ? 'Enabled' : 'Disabled') : 'Unknown');
            setInsightText(bundleInsightDuoTrace, typeof data.duo_desktop_detailed_logging_enabled === 'boolean' ? (data.duo_desktop_detailed_logging_enabled ? 'Enabled' : 'Disabled') : 'Unknown');

            const duoLogs = data.duo_logs && typeof data.duo_logs === 'object' ? data.duo_logs : {};
            const duoStart = String(duoLogs.start || 'Not found');
            const duoEnd = String(duoLogs.end || 'Not found');
            const duoTimeframeText = (duoStart === 'Not found' && duoEnd === 'Not found')
                ? 'Not Found'
                : `${duoStart} -> ${duoEnd}`;
            setInsightText(bundleInsightDuoTimeframe, duoTimeframeText, 'Not Found');

            const ztaLogs = data.zta_logs && typeof data.zta_logs === 'object' ? data.zta_logs : {};
            setInsightText(bundleInsightTimeframe, `${String(ztaLogs.start || 'Not found')} -> ${String(ztaLogs.end || 'Not found')}`);

            const ztaPreviewSignals = data.zta_preview_signals && typeof data.zta_preview_signals === 'object'
                ? data.zta_preview_signals
                : {};
            const tndDetected = ztaPreviewSignals.tnd_detected;
            setInsightText(
                bundleInsightTndDetected,
                typeof tndDetected === 'boolean' ? (tndDetected ? 'Yes' : 'No') : 'No',
                'No'
            );
            const srvConfiguration = ztaPreviewSignals.srv_configuration && typeof ztaPreviewSignals.srv_configuration === 'object'
                ? ztaPreviewSignals.srv_configuration
                : { detected: false, count: 0 };
            setInsightText(
                bundleInsightSrvConfigDetected,
                srvConfiguration.detected ? `Yes (${Number.isFinite(Number(srvConfiguration.count)) ? Number(srvConfiguration.count) : 0})` : 'No',
                'Unknown'
            );

            if (bundleInsightMethodsBody) {
                bundleInsightMethodsBody.innerHTML = '';
                const methods = Array.isArray(enrollmentPreview.methods) ? enrollmentPreview.methods : [];
                if (!methods.length) {
                    const row = document.createElement('tr');
                    row.className = 'border-b border-sky-500/10';
                    row.innerHTML = '<td class="p-2 text-sky-100" colspan="3">No enrollment method traces found in preview scan.</td>';
                    bundleInsightMethodsBody.appendChild(row);
                } else {
                    methods.forEach((methodEntry) => {
                        const row = document.createElement('tr');
                        row.className = 'border-b border-sky-500/10';

                        const methodCell = document.createElement('td');
                        methodCell.className = 'p-2 text-sky-100';
                        methodCell.textContent = String(methodEntry.method || 'Unknown');

                        const attemptCell = document.createElement('td');
                        attemptCell.className = 'p-2 text-sky-100';
                        attemptCell.textContent = String(Number.isFinite(Number(methodEntry.attempt_count)) ? Number(methodEntry.attempt_count) : 0);

                        const outcomeCell = document.createElement('td');
                        outcomeCell.className = 'p-2 text-sky-100';
                        outcomeCell.textContent = String(methodEntry.outcome || 'unknown');

                        row.appendChild(methodCell);
                        row.appendChild(attemptCell);
                        row.appendChild(outcomeCell);
                        bundleInsightMethodsBody.appendChild(row);
                    });
                }
            }

            if (bundleInsightHealthBody) {
                bundleInsightHealthBody.innerHTML = '';
                const configSync = ztaPreviewSignals.configuration_sync_errors && typeof ztaPreviewSignals.configuration_sync_errors === 'object'
                    ? ztaPreviewSignals.configuration_sync_errors
                    : { detected: false, count: 0 };
                const connectivity = ztaPreviewSignals.server_connectivity_errors && typeof ztaPreviewSignals.server_connectivity_errors === 'object'
                    ? ztaPreviewSignals.server_connectivity_errors
                    : { detected: false, count: 0 };
                const healthRows = [
                    {
                        signal: 'Configuration Sync Errors',
                        detected: Boolean(configSync.detected),
                        count: Number.isFinite(Number(configSync.count)) ? Number(configSync.count) : 0,
                    },
                    {
                        signal: 'Server Connectivity Errors',
                        detected: Boolean(connectivity.detected),
                        count: Number.isFinite(Number(connectivity.count)) ? Number(connectivity.count) : 0,
                    },
                ];

                healthRows.forEach((entry) => {
                    const row = document.createElement('tr');
                    row.className = entry.detected
                        ? 'border-b border-rose-500/20 bg-rose-500/5'
                        : 'border-b border-emerald-500/20 bg-emerald-500/5';

                    const signalCell = document.createElement('td');
                    signalCell.className = entry.detected ? 'p-2 text-rose-100' : 'p-2 text-emerald-100';
                    signalCell.textContent = entry.signal;

                    const detectedCell = document.createElement('td');
                    detectedCell.className = entry.detected ? 'p-2 text-rose-200 font-bold' : 'p-2 text-emerald-200 font-bold';
                    detectedCell.textContent = entry.detected ? 'Yes' : 'No';

                    const countCell = document.createElement('td');
                    countCell.className = entry.detected ? 'p-2 text-rose-100' : 'p-2 text-emerald-100';
                    countCell.textContent = String(entry.count);

                    row.appendChild(signalCell);
                    row.appendChild(detectedCell);
                    row.appendChild(countCell);
                    bundleInsightHealthBody.appendChild(row);
                });
            }

            bundleInsightPanel.classList.remove('hidden');
            if (openAgentChatBtn) {
                openAgentChatBtn.classList.remove('hidden');
            }
        }

        function startAgentChatSession(sessionId, moduleName) {
            const resolvedSessionId = String(sessionId || '').trim();
            if (!resolvedSessionId) {
                resetAgentChatCard();
                return;
            }

            currentAnalysisSessionId = resolvedSessionId;
            agentChatHistory = [];

            if (agentChatMessages) {
                agentChatMessages.innerHTML = '';
            }

            if (agentChatCard) {
                agentChatCard.classList.remove('hidden');
            }

            setAgentChatBusy(false);
            setAgentChatStatus(`Ready | Session ${resolvedSessionId.slice(0, 8)} | ${String(moduleName || '').trim() || 'Unknown Module'}`);
            const loweredModule = String(moduleName || '').trim().toLowerCase();
            if (loweredModule === 'bundle preview') {
                appendAgentChatMessage('agent', 'Bundle is ready. Ask me anything from this DART preview, for example: What OS, enrollment method, ORG ID, and log timeframe does this bundle show?');
            } else {
                appendAgentChatMessage('agent', 'Agent session is ready. Ask a question based on the current deterministic analysis, for example: why ZTA enrollment failed?');
            }
        }

        function showAgentChatOnlyPane() {
            if (resultArea) {
                resultArea.classList.remove('hidden');
            }
            setResultOutputPanelVisibility(false);
            resetServerConnectivitySummary();
            resetConfigSyncSummary();
            resetEventViewerSummary();
            resetTndSummary();
            resetUserPauseSummary();
            resetDuoPostureFlowSummary();
            resetAiInsightCard();
            if (spaFlowCandidatesWrap) {
                spaFlowCandidatesWrap.classList.add('hidden');
            }
            if (spaFlowCandidatesList) {
                spaFlowCandidatesList.innerHTML = '';
            }
            if (spaFlowSelectedBadge) {
                spaFlowSelectedBadge.classList.add('hidden');
                spaFlowSelectedBadge.textContent = '';
            }
            if (spaFlowSummary) {
                spaFlowSummary.classList.add('hidden');
                spaFlowSummary.textContent = '';
            }
        }

        function renderDuoPostureFlowSummary(summary) {
            resetDuoPostureFlowSummary();
            if (!duoPostureFlowSummaryWrap || !duoPostureFlowSummaryBody) {
                return;
            }

            const rows = Array.isArray(summary && summary.rows) ? summary.rows : [];
            const filterText = String(summary && summary.filter ? summary.filter : '').trim();
            const timeframeStart = String(summary && summary.timeframe_start ? summary.timeframe_start : 'Unknown');
            const timeframeEnd = String(summary && summary.timeframe_end ? summary.timeframe_end : 'Unknown');
            const timezone = String(summary && summary.timezone ? summary.timezone : '').trim();

            if (duoPostureFlowFilter) {
                duoPostureFlowFilter.textContent = filterText
                    ? `Filter: ${filterText}`
                    : 'Filter: Posture';
            }
            if (duoPostureFlowTotalPatterns) {
                duoPostureFlowTotalPatterns.textContent = `Unique Patterns: ${rows.length}`;
            }
            if (duoPostureFlowTimeRange) {
                duoPostureFlowTimeRange.textContent = `Time Range: ${timeframeStart} -> ${timeframeEnd}${timezone ? ` ${timezone}` : ''}`;
            }

            rows.forEach((row) => {
                const tr = document.createElement('tr');
                tr.className = 'border-b border-sky-500/10';

                const patternCell = document.createElement('td');
                patternCell.className = 'p-2 text-sky-100';
                patternCell.textContent = String(row && row.pattern ? row.pattern : 'Unknown');

                const hitsCell = document.createElement('td');
                hitsCell.className = 'p-2 text-sky-100 font-bold';
                hitsCell.textContent = String(row && Number.isFinite(Number(row.hits)) ? Number(row.hits) : 0);

                const firstSeenCell = document.createElement('td');
                firstSeenCell.className = 'p-2 text-sky-100';
                firstSeenCell.textContent = String(row && row.first_seen ? row.first_seen : 'Unknown');

                const lastSeenCell = document.createElement('td');
                lastSeenCell.className = 'p-2 text-sky-100';
                lastSeenCell.textContent = String(row && row.last_seen ? row.last_seen : 'Unknown');

                const downloadCell = document.createElement('td');
                downloadCell.className = 'p-2';
                const downloadText = String(row && row.download_text ? row.download_text : '').trim();
                if (downloadText) {
                    const filename = String(row && row.download_filename ? row.download_filename : 'duo_posture_transactions.log');
                    const blob = new Blob([downloadText], { type: 'text/plain;charset=utf-8' });
                    const objectUrl = URL.createObjectURL(blob);
                    duoPostureSummaryDownloadUrls.push(objectUrl);

                    const link = document.createElement('a');
                    link.href = objectUrl;
                    link.download = filename;
                    link.className = 'inline-flex items-center rounded border border-emerald-400/40 px-2 py-1 text-xs font-bold tracking-wide text-emerald-100 hover:bg-emerald-500/10';
                    link.textContent = 'Download';
                    downloadCell.appendChild(link);
                } else {
                    const emptyText = document.createElement('span');
                    emptyText.className = 'text-xs text-sky-200/70';
                    emptyText.textContent = 'No lines';
                    downloadCell.appendChild(emptyText);
                }

                tr.appendChild(patternCell);
                tr.appendChild(hitsCell);
                tr.appendChild(firstSeenCell);
                tr.appendChild(lastSeenCell);
                tr.appendChild(downloadCell);
                duoPostureFlowSummaryBody.appendChild(tr);
            });

            if (!rows.length) {
                const tr = document.createElement('tr');
                const td = document.createElement('td');
                td.colSpan = 5;
                td.className = 'p-3 text-sky-200/80 text-sm';
                td.textContent = 'No posture pattern rows were returned.';
                tr.appendChild(td);
                duoPostureFlowSummaryBody.appendChild(tr);
            }

            duoPostureFlowSummaryWrap.classList.remove('hidden');
        }

        // Parse a per-source-port connectivity download blob into trace lines the
        // Visual Flow Analyzer can render (each line carries its log location so the
        // full-log highlight panel can point at the matched line).
        function buildConnectivityTraceLines(downloadText) {
            const out = [];
            const locRe = /^(.+:L\d+)\s+\[.*\]\s*$/;
            let pendingLoc = '';
            String(downloadText || '').split('\n').forEach((raw) => {
                const trimmed = raw.trim();
                if (!trimmed) {
                    return;
                }
                if (trimmed.startsWith('[Destination:')) {
                    return;
                }
                const locMatch = trimmed.match(locRe);
                if (locMatch) {
                    pendingLoc = locMatch[1];
                    return;
                }
                out.push(pendingLoc ? `${pendingLoc} ${trimmed}` : trimmed);
                pendingLoc = '';
            });
            return out;
        }

        function buildConnectivityDiagramSvg(destGroups, reachableTime, unreachableTime) {
            const esc = (value) => escapeHtml(String(value == null ? '' : value));
            const truncate = (value, max) => {
                const text = String(value || '');
                return text.length > max ? text.slice(0, max - 1) + '\u2026' : text;
            };

            if (!destGroups.length) {
                return '<div class="p-6 text-center text-slate-500 text-sm">No outbound destinations were reached during this time frame.</div>';
            }

            const width = 880;
            const rowH = 62;
            const top = 30;
            const height = Math.max(top * 2 + destGroups.length * rowH, 260);
            const hubX = 30;
            const hubW = 180;
            const hubH = 54;
            const hubCx = hubX + hubW / 2;
            const hubCy = height / 2;
            const nodeX = 540;
            const nodeW = 312;
            const nodeH = 48;
            const maxHits = destGroups.reduce((max, group) => Math.max(max, group.hits), 1);
            const anyError = destGroups.some((group) => group.hasError);

            let connectors = '';
            let nodes = '';

            destGroups.forEach((group, index) => {
                const nodeCy = top + rowH * index + rowH / 2;
                const nodeY = nodeCy - nodeH / 2;
                const intensity = Math.max(0.25, group.hits / maxHits);
                const strokeW = (1.5 + intensity * 4).toFixed(1);
                const controlX = (hubX + hubW + nodeX) / 2;
                const err = !!group.hasError;
                const lineColor = err ? '#dc2626' : '#0284c7';
                const nodeFill = err
                    ? `rgba(239,68,68,${(0.10 + intensity * 0.16).toFixed(3)})`
                    : `rgba(14,165,233,${(0.08 + intensity * 0.18).toFixed(3)})`;
                const nodeStroke = err ? '#dc2626' : '#0284c7';
                const destFill = err ? '#991b1b' : '#0c4a6e';
                const subFill = err ? '#b91c1c' : '#0369a1';

                connectors += `<path d="M ${hubX + hubW} ${hubCy} C ${controlX} ${hubCy}, ${controlX} ${nodeCy}, ${nodeX} ${nodeCy}" fill="none" stroke="${lineColor}" stroke-opacity="${(0.35 + intensity * 0.5).toFixed(2)}" stroke-width="${strokeW}" />`;
                connectors += `<circle cx="${nodeX}" cy="${nodeCy}" r="3.5" fill="${lineColor}" />`;

                const portCount = group.flows.length;
                const portsText = `${portCount} diff Flow${portCount === 1 ? '' : 's'}${err ? ' \u2014 problematic' : ''}`;

                nodes += `
                    <g>
                        <rect x="${nodeX}" y="${nodeY}" rx="9" ry="9" width="${nodeW}" height="${nodeH}" fill="${nodeFill}" stroke="${nodeStroke}" stroke-opacity="0.6" />
                        <text x="${nodeX + 14}" y="${nodeCy - 4}" fill="${destFill}" font-size="14.5" font-weight="700" font-family="monospace">${esc(truncate(group.destination, 36))}</text>
                        <text x="${nodeX + 14}" y="${nodeCy + 15}" fill="${subFill}" font-size="12" font-family="monospace">${esc(portsText)}</text>
                    </g>`;
            });

            const infoTop = hubCy + hubH / 2 + 26;
            const info = `
                <g font-family="ui-sans-serif, system-ui, sans-serif">
                    <text x="${hubX}" y="${infoTop}" font-size="13"><tspan fill="#475569" font-weight="700">Proxy reachable:</tspan> <tspan fill="#15803d" font-weight="700">${esc(reachableTime)}</tspan></text>
                    <text x="${hubX}" y="${infoTop + 22}" font-size="13"><tspan fill="#475569" font-weight="700">Proxy unreachable:</tspan> <tspan fill="#b91c1c" font-weight="700">${esc(unreachableTime)}</tspan></text>
                    <text x="${hubX}" y="${infoTop + 48}" font-size="13" fill="#334155">During this window, ${destGroups.length} destination${destGroups.length === 1 ? '' : 's'} ${destGroups.length === 1 ? 'was' : 'were'} accessed:</text>
                    ${anyError ? `<text x="${hubX}" y="${infoTop + 72}" font-size="12.5"><tspan fill="#dc2626" font-weight="800">\u25A0</tspan> <tspan fill="#334155">Flows shown in red had connection problems in the logs</tspan></text>` : ''}
                </g>`;

            const hub = `
                <g>
                    <rect x="${hubX}" y="${hubCy - hubH / 2}" rx="12" ry="12" width="${hubW}" height="${hubH}" fill="rgba(37,99,235,0.12)" stroke="#2563eb" stroke-opacity="0.8" stroke-width="1.5" />
                    <text x="${hubCx}" y="${hubCy + 5}" fill="#1e3a8a" font-size="14" font-weight="800" text-anchor="middle">ZTA Client</text>
                </g>`;

            return `<svg viewBox="0 0 ${width} ${height}" width="100%" preserveAspectRatio="xMidYMid meet" style="min-width:680px; display:block;">${connectors}${hub}${info}${nodes}</svg>`;
        }

        function renderServerConnectivitySummary(summary) {
            resetServerConnectivitySummary();
            if (!serverConnectivitySummaryWrap || !serverConnectivityDiagram) {
                return;
            }

            const normalizeSummaryTimeLabel = (value) => {
                return String(value || 'Unknown')
                    .replace(/\s+Finland\s+Local\s+Time\b/gi, '')
                    .replace(/\s+Local\s+Time\b/gi, '')
                    .trim();
            };

            // Derive a flow's own time frame from the timestamps embedded in its
            // captured trace logs (download_text header lines look like
            // "<path>:L123 [2026-06-01 14:37:53.809459]"). Returns {start, end}
            // or null when no timestamps were captured.
            const extractFlowTimeframe = (downloadText) => {
                const text = String(downloadText || '');
                const stampPattern = /:L\d+\s+\[([^\]]+)\]/g;
                const stamps = [];
                let match;
                while ((match = stampPattern.exec(text)) !== null) {
                    const value = String(match[1] || '').trim();
                    if (value && value.toLowerCase() !== 'unknown') {
                        stamps.push(value);
                    }
                }
                if (!stamps.length) {
                    return null;
                }
                const parsed = stamps
                    .map((value) => ({ value, ms: Date.parse(value.replace(' ', 'T')) }))
                    .filter((item) => !Number.isNaN(item.ms));
                if (parsed.length) {
                    parsed.sort((left, right) => left.ms - right.ms);
                    return { start: parsed[0].value, end: parsed[parsed.length - 1].value };
                }
                const sorted = stamps.slice().sort();
                return { start: sorted[0], end: sorted[sorted.length - 1] };
            };

            const categories = Array.isArray(summary && summary.categories)
                ? summary.categories
                : [];
            const timeframeStart = normalizeSummaryTimeLabel(
                summary && summary.timeframe_start ? summary.timeframe_start : 'Unknown'
            );
            const timeframeEnd = normalizeSummaryTimeLabel(
                summary && summary.timeframe_end ? summary.timeframe_end : 'Unknown'
            );

            // Separate the umbrella "Proxy Connectivity" category from the per-destination spokes.
            let proxyCategory = null;
            const destinationCategories = [];
            categories.forEach((category) => {
                if (category && category.id === 'proxy_connectivity_transition') {
                    proxyCategory = category;
                } else if (category) {
                    destinationCategories.push(category);
                }
            });

            // Group spokes by destination (label format "<destination> | srcPort <port>").
            const groups = new Map();
            destinationCategories.forEach((category) => {
                const label = String(category.label || '');
                const match = label.match(/^(.*?)\s*\|\s*srcPort\s*(\S+)\s*$/i);
                const destination = ((match ? match[1] : label).trim()) || 'Unknown destination';
                const srcPort = match ? match[2].trim() : '';
                let group = groups.get(destination);
                if (!group) {
                    group = { destination: destination, hits: 0, flows: [], downloads: [] };
                    groups.set(destination, group);
                }
                const categoryHits = Number(category.hit_count) || 0;
                group.hits += categoryHits;
                group.flows.push({ srcPort: srcPort || '?', hits: categoryHits, category: category });
                const downloadText = stripSuppressedOutputLines(category.download_text || '');
                if (downloadText) {
                    group.downloads.push(downloadText);
                }
            });

            const destGroups = [...groups.values()].sort((left, right) => right.hits - left.hits);
            destGroups.forEach((group) => {
                group.flows.sort((left, right) => right.hits - left.hits);
            });

            // Flag destinations whose captured flow logs show connection failures so
            // the diagram can mark them red (problematic during this window).
            const connectivityErrorPattern = /(unreachable|timed?\s*out|timeout|refused|connection reset|reset by peer|forcibly closed|connect\s*failure|connectfailure|connect\s*error|connecterror|\bfailed\b|\bfailure\b|no route|aborted|\bdenied\b|unable to connect|cannot connect|could not connect|connection (failed|error))/i;
            destGroups.forEach((group) => {
                group.flows.forEach((flow) => {
                    flow.hasError = buildConnectivityTraceLines(flow.category && flow.category.download_text)
                        .some((line) => connectivityErrorPattern.test(line));
                });
                group.hasError = group.flows.some((flow) => flow.hasError);
            });

            if (serverConnectivityTimeRange) {
                serverConnectivityTimeRange.textContent = `Time Range: ${timeframeStart} -> ${timeframeEnd}`;
            }

            serverConnectivityDiagram.innerHTML = buildConnectivityDiagramSvg(destGroups, timeframeStart, timeframeEnd);

            // Status checks captured within the proxy Ok -> Unreachable window.
            if (serverConnectivityStatusChecks) {
                serverConnectivityStatusChecks.innerHTML = '';
                const pause = summary && summary.proxy_config_pause;
                const netChange = summary && summary.network_change;

                const makeStatusCard = (titleText) => {
                    const card = document.createElement('div');
                    card.className = 'rounded-lg border border-sky-500/25 bg-white/70 p-3';
                    const heading = document.createElement('div');
                    heading.className = 'mb-2 text-sm font-bold uppercase tracking-wide text-sky-800';
                    heading.textContent = titleText;
                    card.appendChild(heading);
                    return card;
                };

                if (pause && pause.found) {
                    const card = makeStatusCard('Proxy Config Pause Status');
                    const summaryLine = document.createElement('div');
                    summaryLine.className = pause.status_changed
                        ? 'mb-2 text-sm font-semibold text-amber-700'
                        : 'mb-2 text-sm font-semibold text-emerald-700';
                    summaryLine.textContent = pause.status_changed
                        ? '\u26a0 Proxy status changed (Active \u21c4 Paused) during this window'
                        : '\u2714 No proxy status change \u2014 configurations stayed the same';
                    card.appendChild(summaryLine);

                    (pause.configs || []).forEach((cfg) => {
                        const row = document.createElement('div');
                        row.className = 'flex items-center justify-between text-sm text-slate-700';
                        const name = document.createElement('span');
                        name.textContent = cfg.label;
                        const status = document.createElement('span');
                        const isActive = String(cfg.status || '').toLowerCase() === 'active';
                        status.className = isActive ? 'font-bold text-emerald-700' : 'font-bold text-red-700';
                        status.textContent = cfg.changed && cfg.transition ? cfg.transition : (cfg.status || 'Unknown');
                        row.appendChild(name);
                        row.appendChild(status);
                        card.appendChild(row);
                    });

                    if (pause.timestamp && pause.timestamp !== 'Unknown') {
                        const ts = document.createElement('div');
                        ts.className = 'mt-2 text-xs text-slate-500';
                        ts.textContent = 'Last updated: ' + pause.timestamp;
                        card.appendChild(ts);
                    }
                    serverConnectivityStatusChecks.appendChild(card);
                }

                if (netChange && netChange.found) {
                    const card = makeStatusCard('Network Change Detection');
                    const summaryLine = document.createElement('div');
                    summaryLine.className = netChange.detected
                        ? 'mb-2 text-sm font-semibold text-amber-700'
                        : 'mb-2 text-sm font-semibold text-emerald-700';
                    summaryLine.textContent = netChange.detected
                        ? '\u26a0 Network change detected during this window'
                        : '\u2714 No network change detected';
                    card.appendChild(summaryLine);

                    if ((netChange.events || []).length) {
                        const intro = document.createElement('div');
                        intro.className = 'mb-1 text-sm text-slate-700';
                        intro.textContent = 'OnNetworkChange events:';
                        card.appendChild(intro);
                        (netChange.events || []).forEach((evt) => {
                            const row = document.createElement('div');
                            row.className = 'text-sm text-slate-700';
                            row.textContent = '\u2022 ' + evt;
                            card.appendChild(row);
                        });
                    }

                    if ((netChange.subscribers || []).length) {
                        const intro = document.createElement('div');
                        intro.className = 'mb-1 mt-2 text-sm text-slate-700';
                        intro.textContent = 'Debounce timers restarted for:';
                        card.appendChild(intro);
                        (netChange.subscribers || []).forEach((sub) => {
                            const row = document.createElement('div');
                            row.className = 'flex items-center justify-between text-sm text-slate-700';
                            const name = document.createElement('span');
                            name.textContent = sub.name;
                            const tmo = document.createElement('span');
                            tmo.className = 'text-slate-500';
                            tmo.textContent = 'timeout ' + sub.timeout + ' ms';
                            row.appendChild(name);
                            row.appendChild(tmo);
                            card.appendChild(row);
                        });
                    }

                    if (netChange.timestamp && netChange.timestamp !== 'Unknown') {
                        const ts = document.createElement('div');
                        ts.className = 'mt-2 text-xs text-slate-500';
                        ts.textContent = 'Detected at: ' + netChange.timestamp;
                        card.appendChild(ts);
                    }
                    serverConnectivityStatusChecks.appendChild(card);
                }
            }

            // Per-destination flow section: each source port gets a Visual Flow Analyzer
            // button (full logs with the matched line highlighted) plus a download link.
            if (serverConnectivityDownloads) {
                serverConnectivityDownloads.innerHTML = '';

                const registerDownloadUrl = (text, filename) => {
                    const clean = stripSuppressedOutputLines(text || '');
                    if (!clean) {
                        return null;
                    }
                    const blob = new Blob([clean], { type: 'text/plain;charset=utf-8' });
                    const objectUrl = URL.createObjectURL(blob);
                    serverConnectivitySummaryDownloadUrls.push(objectUrl);
                    return { url: objectUrl, filename: filename };
                };

                if (proxyCategory) {
                    const proxyDownload = registerDownloadUrl(
                        proxyCategory.download_text,
                        String(proxyCategory.download_filename || 'server_connectivity_proxy_connectivity_transition.log')
                    );
                    if (proxyDownload) {
                        const link = document.createElement('a');
                        link.href = proxyDownload.url;
                        link.download = proxyDownload.filename;
                        link.className = 'inline-flex items-center rounded border border-sky-500/50 px-3 py-1.5 text-sm font-bold tracking-wide text-sky-700 hover:bg-sky-500/10';
                        link.textContent = 'Download All Proxy Connectivity Logs';
                        serverConnectivityDownloads.appendChild(link);
                    }
                }

                destGroups.forEach((group) => {
                    const groupWrap = document.createElement('div');
                    groupWrap.className = 'w-full mt-3 rounded-lg border border-sky-500/25 bg-white/60 p-3';

                    const title = document.createElement('div');
                    title.className = group.hasError
                        ? 'mb-2 text-base font-bold text-red-700'
                        : 'mb-2 text-base font-bold text-sky-800';
                    title.textContent = group.hasError
                        ? `\u26a0 ${group.destination}  \u00b7  problematic`
                        : group.destination;
                    groupWrap.appendChild(title);

                    const btnRow = document.createElement('div');
                    btnRow.className = 'flex flex-wrap items-start gap-2';

                    group.flows.forEach((flow) => {
                        const flowTimeframe = extractFlowTimeframe(flow.category && flow.category.download_text);
                        const flowStart = flowTimeframe ? flowTimeframe.start : timeframeStart;
                        const flowEnd = flowTimeframe ? flowTimeframe.end : timeframeEnd;

                        const flowWrap = document.createElement('div');
                        flowWrap.className = 'flex flex-col gap-0.5';

                        const flowButton = document.createElement('button');
                        flowButton.type = 'button';
                        flowButton.className = flow.hasError
                            ? 'flow-visual-btn rounded border border-red-500/60 bg-red-500/5 px-3 py-1.5 text-sm font-bold tracking-wide text-red-700 hover:bg-red-500/15'
                            : 'flow-visual-btn rounded border border-sky-500/50 px-3 py-1.5 text-sm font-bold tracking-wide text-sky-700 hover:bg-sky-500/10';
                        flowButton.textContent = flow.hasError
                            ? `\u26a0 Visual Flow Analyzer \u00b7 srcPort ${flow.srcPort} (${flow.hits})`
                            : `Visual Flow Analyzer \u00b7 srcPort ${flow.srcPort} (${flow.hits})`;
                        flowButton.addEventListener('click', () => {
                            const traceLines = buildConnectivityTraceLines(flow.category.download_text);
                            if (!traceLines.length) {
                                alert('No trace lines were captured for source port ' + flow.srcPort + '.');
                                return;
                            }
                            const session = {
                                srcPort: flow.srcPort,
                                process: '',
                                ruleType: '',
                                firstTime: flowStart,
                                lastTime: flowEnd,
                            };
                            const destinationRow = { destination: group.destination, realDestinationIp: '' };
                            const model = flowUtils.buildFlowSequenceModel(session, destinationRow, traceLines);
                            openFlowVisualTab(
                                model,
                                'Visual Flow Analyzer \u00b7 srcPort ' + flow.srcPort + ' \u00b7 ' + group.destination
                            );
                        });
                        flowWrap.appendChild(flowButton);

                        if (flowTimeframe) {
                            const timeCaption = document.createElement('span');
                            timeCaption.className = 'dh-flow-timeframe px-1 text-[11px] font-mono';
                            timeCaption.textContent = flowStart === flowEnd
                                ? `\u23f1 ${flowStart}`
                                : `\u23f1 ${flowStart} \u2192 ${flowEnd}`;
                            flowWrap.appendChild(timeCaption);
                        }

                        btnRow.appendChild(flowWrap);
                    });

                    const safeName = flowUtils && typeof flowUtils.sanitizeFilenamePart === 'function'
                        ? flowUtils.sanitizeFilenamePart(group.destination)
                        : String(group.destination).replace(/[^a-z0-9]+/gi, '_');
                    const groupDownload = registerDownloadUrl(
                        group.downloads.join('\n\n'),
                        `server_connectivity_${safeName}.log`
                    );
                    if (groupDownload) {
                        const link = document.createElement('a');
                        link.href = groupDownload.url;
                        link.download = groupDownload.filename;
                        link.className = 'inline-flex items-center rounded border border-emerald-500/50 px-3 py-1.5 text-sm font-bold tracking-wide text-emerald-700 hover:bg-emerald-500/10';
                        link.textContent = 'Download Logs';
                        btnRow.appendChild(link);
                    }

                    groupWrap.appendChild(btnRow);
                    serverConnectivityDownloads.appendChild(groupWrap);
                });
            }

            serverConnectivitySummaryWrap.classList.remove('hidden');
        }

        function resetConfigSyncSummary() {
            if (configSyncSummaryDownloadUrls.length) {
                configSyncSummaryDownloadUrls.forEach((url) => {
                    URL.revokeObjectURL(url);
                });
            }
            configSyncSummaryDownloadUrls = [];
            if (configSyncEnrollment) {
                configSyncEnrollment.textContent = '';
            }
            if (configSyncTimeRange) {
                configSyncTimeRange.textContent = '';
            }
            [configSyncVerdict, configSyncStatCards, configSyncScheduler, configSyncAttempts, configSyncDownloads].forEach((el) => {
                if (el) {
                    el.innerHTML = '';
                }
            });
            if (configSyncScheduler) {
                configSyncScheduler.classList.add('hidden');
            }
            if (configSyncSummaryWrap) {
                configSyncSummaryWrap.classList.add('hidden');
            }
        }

        function buildConfigSyncFlowModel(summary, attemptsArg) {
            const attempts = Array.isArray(attemptsArg)
                ? attemptsArg
                : (Array.isArray(summary.attempts) ? summary.attempts : []);
            const isMulti = attempts.length > 1;
            const scheduler = summary.scheduler || {};
            const logLines = [];
            const events = [];
            let detectedUrl = String(summary.config_sync_url || '').trim();

            // Extract a config sync URL from a raw line (fallback when the backend
            // did not surface one). Handles both "URL: https://..." and
            // "configSyncUrl=https://..." forms.
            const extractUrl = (text) => {
                const m = String(text || '').match(/(?:URL:\s*|configSyncUrl=)(https?:\/\/[^\s;,)]+)/i);
                return m ? m[1].replace(/[.,;"']+$/, '') : '';
            };

            // Map a raw config-sync log line to a labelled flow event. Returns null
            // for lines that are not notable flow steps.
            const classifyEvent = (text, lineType, reason) => {
                const t = String(text || '');
                if (/Initiated\s+POST\s+HTTP\s+request/i.test(t)) {
                    return { label: 'Config Sync initiated (POST)', direction: 'out', error: false };
                }
                if (/sent\s+config\s+sync\s+request/i.test(t)) {
                    return { label: 'Sent config sync request', direction: 'out', error: false };
                }
                const statusMatch = t.match(/http_status[:=]\s*(\d{3})/i);
                if (/received\s+sync\s+response/i.test(t) || statusMatch) {
                    const code = statusMatch ? parseInt(statusMatch[1], 10) : null;
                    const isErr = code != null && code >= 400;
                    return {
                        label: code != null ? `Sync response received (HTTP ${code})` : 'Sync response received',
                        direction: 'in',
                        error: isErr,
                    };
                }
                if (/client already has the latest config/i.test(t)) {
                    return { label: 'Client already has latest config', direction: 'in', error: false };
                }
                if (/config sync was successful/i.test(t)) {
                    return { label: 'Config sync successful', direction: 'in', error: false };
                }
                if (/logConfigSyncStats|Config sync stats for Enrollment/i.test(t)) {
                    return { label: 'Config sync stats logged', direction: 'self', error: false };
                }
                if (/scheduleConfigSync/i.test(t)) {
                    return { label: 'Next sync scheduled', direction: 'self', error: false };
                }
                if (lineType === 'failure') {
                    return { label: `${reason || 'Error in response'} \u2014 no successful response`, direction: 'in', error: true };
                }
                if (lineType === 'success') {
                    return { label: reason || 'Sync successful', direction: 'in', error: false };
                }
                return null;
            };

            attempts.forEach((attempt) => {
                (Array.isArray(attempt.lines) ? attempt.lines : []).forEach((ln) => {
                    const logIndex = logLines.length;
                    const text = String(ln.text || '');
                    logLines.push(`${ln.location} [${ln.timestamp}] ${text}`);
                    if (!detectedUrl) {
                        detectedUrl = extractUrl(text);
                    }
                    const ev = classifyEvent(text, ln.type, ln.reason);
                    if (ev) {
                        const attemptTag = isMulti ? `Request ${attempt.index}: ` : '';
                        events.push({
                            label: `${attemptTag}${ev.label}`,
                            timestamp: ln.timestamp,
                            raw: text,
                            logIndex,
                            error: ev.error,
                            direction: ev.direction,
                        });
                    }
                });
            });

            const enrollmentIds = Array.isArray(summary.enrollment_ids) ? summary.enrollment_ids : [];
            const urlValue = detectedUrl;
            const sentTotal = attempts.reduce((sum, a) => sum + (Number(a.sent) || 0), 0);
            const successTotal = attempts.reduce((sum, a) => sum + (Number(a.success) || 0), 0);
            const intervalText = scheduler.interval_seconds && scheduler.interval_seconds !== 'Unknown'
                ? `${scheduler.interval_seconds} s`
                : 'Unknown';
            const summaryBits = [
                enrollmentIds.length ? `Enrollment: ${enrollmentIds.join(', ')}` : '',
                `Time Range: ${summary.time_range_display || 'Unknown'}`,
                urlValue ? `Config Sync URL: ${urlValue}` : '',
                `Last Sync Attempt: ${scheduler.last_sync_attempt || 'Unknown'}`,
                `Last Sync Response: ${scheduler.last_sync_response || 'Unknown'}`,
                `Sync Interval: ${intervalText}`,
                `Next Sync: ${scheduler.next_sync || 'Unknown'}`,
                `Sent: ${sentTotal} \u00b7 Success: ${successTotal}`,
            ].filter(Boolean);

            return {
                clientLabel: 'ZTA Client',
                proxyLabel: 'Config Sync Server',
                bothLabel: 'Config payload',
                events,
                logLines,
                summaryBits,
                destination: urlValue || 'Config Sync Server',
                eventCount: events.length,
                firstTime: summary.timeframe_start || '',
                lastTime: summary.timeframe_end || '',
                endpoints: urlValue ? [{ label: 'Config Sync', method: 'POST', url: urlValue }] : [],
            };
        }

        function renderConfigSyncSummary(summary) {
            resetConfigSyncSummary();
            if (!configSyncSummaryWrap || !summary) {
                return;
            }

            const verdict = String(summary.verdict || 'none');
            const enrollmentIds = Array.isArray(summary.enrollment_ids) ? summary.enrollment_ids : [];
            if (configSyncEnrollment) {
                configSyncEnrollment.textContent = enrollmentIds.length
                    ? `Enrollment ID${enrollmentIds.length > 1 ? 's' : ''}: ${enrollmentIds.join(', ')}`
                    : 'Enrollment ID: Unknown';
            }
            if (configSyncTimeRange) {
                configSyncTimeRange.textContent = `Time Range: ${summary.time_range_display || 'Unknown'}`;
            }

            // Per request, the inline panel is collapsed to just the two action
            // buttons (Open Visual Flow Analyzer + Download). All detailed views
            // (verdict, stat cards, scheduler, success/failure lists and the raw
            // trace) now live inside the Visual Flow Analyzer. Flip this flag to
            // restore the inline detail sections.
            const SHOW_CONFIG_SYNC_DETAILS = false;

            // Verdict banner.
            if (SHOW_CONFIG_SYNC_DETAILS && configSyncVerdict) {
                const verdictMeta = {
                    healthy: { cls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200', text: '\u2714 Configuration sync completed successfully' },
                    partial: { cls: 'border-amber-500/40 bg-amber-500/10 text-amber-200', text: '\u26a0 Configuration sync partially succeeded \u2014 some requests had no successful response' },
                    failed: { cls: 'border-red-500/40 bg-red-500/10 text-red-200', text: '\u2716 Configuration sync failed \u2014 no successful responses' },
                    none: { cls: 'border-slate-500/40 bg-slate-500/10 text-slate-200', text: 'No configuration sync requests were found in this window' },
                };
                const meta = verdictMeta[verdict] || verdictMeta.none;
                const banner = document.createElement('div');
                banner.className = `rounded-lg border px-3 py-2 text-sm font-semibold ${meta.cls}`;
                banner.textContent = meta.text;
                configSyncVerdict.appendChild(banner);
            }

            // Stat cards.
            if (SHOW_CONFIG_SYNC_DETAILS && configSyncStatCards) {
                const sent = Number(summary.sent_requests) || 0;
                const success = Number(summary.success_responses) || 0;
                const failedCount = Math.max(sent - success, 0);
                const rate = sent > 0 ? Math.round((success / sent) * 100) : 0;
                const cards = [
                    { label: 'Sent Requests', value: String(sent), tone: 'text-sky-200' },
                    { label: 'Successful', value: String(success), tone: 'text-emerald-300' },
                    { label: 'No Response', value: String(failedCount), tone: failedCount ? 'text-red-300' : 'text-slate-300' },
                    { label: 'Success Rate', value: sent > 0 ? `${rate}%` : '\u2014', tone: rate >= 100 ? 'text-emerald-300' : (rate > 0 ? 'text-amber-300' : 'text-slate-300') },
                ];
                cards.forEach((card) => {
                    const cardEl = document.createElement('div');
                    cardEl.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-3';
                    const value = document.createElement('div');
                    value.className = `text-2xl font-bold ${card.tone}`;
                    value.textContent = card.value;
                    const label = document.createElement('div');
                    label.className = 'mt-1 text-xs uppercase tracking-wide text-sky-200/70';
                    label.textContent = card.label;
                    cardEl.appendChild(value);
                    cardEl.appendChild(label);
                    configSyncStatCards.appendChild(cardEl);
                });
            }

            // Scheduler timeline.
            if (SHOW_CONFIG_SYNC_DETAILS && configSyncScheduler) {
                const scheduler = summary.scheduler || {};
                configSyncScheduler.classList.remove('hidden');
                const heading = document.createElement('div');
                heading.className = 'mb-2 text-xs font-bold uppercase tracking-wide text-sky-300';
                heading.textContent = 'Scheduler';
                configSyncScheduler.appendChild(heading);
                const grid = document.createElement('div');
                grid.className = 'grid grid-cols-1 gap-2 sm:grid-cols-2';
                const rows = [
                    ['Last Sync Attempt', scheduler.last_sync_attempt],
                    ['Last Sync Response', scheduler.last_sync_response],
                    ['Sync Interval', scheduler.interval_seconds && scheduler.interval_seconds !== 'Unknown' ? `${scheduler.interval_seconds} s` : 'Unknown'],
                    ['Next Sync', scheduler.next_sync],
                ];
                rows.forEach(([label, value]) => {
                    const row = document.createElement('div');
                    row.className = 'flex items-center justify-between gap-3 text-sm';
                    const name = document.createElement('span');
                    name.className = 'text-sky-200/70';
                    name.textContent = label;
                    const val = document.createElement('span');
                    val.className = 'font-semibold text-sky-100';
                    val.textContent = value || 'Unknown';
                    row.appendChild(name);
                    row.appendChild(val);
                    grid.appendChild(row);
                });
                configSyncScheduler.appendChild(grid);
            }

            // URL + clickable success/failure navigation + per-attempt log lines.
            if (SHOW_CONFIG_SYNC_DETAILS && configSyncAttempts) {
                const attempts = Array.isArray(summary.attempts) ? summary.attempts : [];

                // Scroll to and briefly highlight a log line by its id.
                const flashConfigSyncLine = (lineId) => {
                    if (!lineId) {
                        return;
                    }
                    const el = document.getElementById(lineId);
                    if (!el) {
                        return;
                    }
                    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    el.classList.add('ring-2', 'ring-amber-400', 'rounded');
                    window.setTimeout(() => {
                        el.classList.remove('ring-2', 'ring-amber-400', 'rounded');
                    }, 1600);
                };

                // Config Sync URL.
                const urlValue = String(summary.config_sync_url || '').trim();
                if (urlValue) {
                    const urlCard = document.createElement('div');
                    urlCard.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-3';
                    const urlLabel = document.createElement('div');
                    urlLabel.className = 'text-xs font-bold uppercase tracking-wide text-sky-300';
                    urlLabel.textContent = 'Config Sync URL';
                    const urlText = document.createElement('div');
                    urlText.className = 'mt-1 break-all font-mono text-sm text-sky-100';
                    urlText.textContent = urlValue;
                    urlCard.appendChild(urlLabel);
                    urlCard.appendChild(urlText);
                    configSyncAttempts.appendChild(urlCard);
                }

                // Gather success + failure lines across all attempts.
                const successLines = [];
                const failureLines = [];
                attempts.forEach((attempt) => {
                    (Array.isArray(attempt.lines) ? attempt.lines : []).forEach((ln) => {
                        if (ln.type === 'success') {
                            successLines.push(ln);
                        } else if (ln.type === 'failure') {
                            failureLines.push(ln);
                        }
                    });
                });

                // Clickable results navigation (Successful / Failures).
                if (successLines.length || failureLines.length) {
                    const navWrap = document.createElement('div');
                    navWrap.className = 'grid grid-cols-1 gap-3 md:grid-cols-2';

                    const buildResultList = (titleText, items, tone) => {
                        const col = document.createElement('div');
                        col.className = `rounded-lg border p-3 ${tone.border} ${tone.bg}`;
                        const head = document.createElement('div');
                        head.className = `mb-2 text-xs font-bold uppercase tracking-wide ${tone.title}`;
                        head.textContent = `${titleText} (${items.length})`;
                        col.appendChild(head);
                        if (!items.length) {
                            const empty = document.createElement('div');
                            empty.className = 'text-xs text-slate-400';
                            empty.textContent = 'None';
                            col.appendChild(empty);
                        } else {
                            const list = document.createElement('div');
                            list.className = 'flex flex-col gap-1';
                            items.forEach((ln) => {
                                const btn = document.createElement('button');
                                btn.type = 'button';
                                btn.className = `flex w-full items-center justify-between gap-2 rounded px-2 py-1 text-left text-xs ${tone.itemText} ${tone.itemHover}`;
                                const label = document.createElement('span');
                                label.className = 'font-semibold';
                                label.textContent = ln.reason || titleText;
                                const meta = document.createElement('span');
                                meta.className = 'shrink-0 text-[11px] text-slate-400';
                                meta.textContent = ln.timestamp || '';
                                btn.appendChild(label);
                                btn.appendChild(meta);
                                btn.addEventListener('click', () => flashConfigSyncLine(ln.id));
                                list.appendChild(btn);
                            });
                            col.appendChild(list);
                        }
                        return col;
                    };

                    navWrap.appendChild(buildResultList('Successful', successLines, {
                        border: 'border-emerald-500/30',
                        bg: 'bg-emerald-500/5',
                        title: 'text-emerald-300',
                        itemText: 'text-emerald-200',
                        itemHover: 'hover:bg-emerald-500/10',
                    }));
                    navWrap.appendChild(buildResultList('Failures', failureLines, {
                        border: 'border-red-500/30',
                        bg: 'bg-red-500/5',
                        title: 'text-red-300',
                        itemText: 'text-red-200',
                        itemHover: 'hover:bg-red-500/10',
                    }));
                    configSyncAttempts.appendChild(navWrap);
                }

                // Per-attempt sections with anchored, color-coded raw log lines.
                attempts.forEach((attempt) => {
                    const wrap = document.createElement('div');
                    wrap.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-3';

                    const header = document.createElement('div');
                    header.className = 'mb-2 flex items-center justify-between';
                    const title = document.createElement('div');
                    title.className = 'text-sm font-bold text-sky-200';
                    title.textContent = summary.multiple_attempts ? `Config Sync Attempt ${attempt.index}` : 'Config Sync Trace';
                    const badge = document.createElement('div');
                    const ok = (Number(attempt.success) || 0) >= (Number(attempt.sent) || 0) && (Number(attempt.sent) || 0) > 0;
                    badge.className = ok
                        ? 'text-xs font-semibold text-emerald-300'
                        : 'text-xs font-semibold text-amber-300';
                    badge.textContent = `sent ${Number(attempt.sent) || 0} \u00b7 success ${Number(attempt.success) || 0}`;
                    header.appendChild(title);
                    header.appendChild(badge);
                    wrap.appendChild(header);

                    const lines = Array.isArray(attempt.lines) ? attempt.lines : [];
                    if (lines.length) {
                        const logBox = document.createElement('div');
                        logBox.className = 'max-h-64 overflow-auto rounded bg-black/40 p-2 text-xs leading-relaxed';
                        lines.forEach((ln) => {
                            const row = document.createElement('div');
                            let accent = 'border-transparent text-slate-400';
                            if (ln.type === 'success') {
                                accent = 'border-emerald-400/70 text-emerald-200/90';
                            } else if (ln.type === 'failure') {
                                accent = 'border-red-400/70 text-red-200/90';
                            }
                            row.className = `border-l-2 pl-2 py-0.5 whitespace-pre-wrap font-mono ${accent}`;
                            if (ln.id) {
                                row.id = String(ln.id);
                            }
                            row.textContent = `${ln.location} [${ln.timestamp}]\n${ln.text}`;
                            logBox.appendChild(row);
                        });
                        wrap.appendChild(logBox);
                    }
                    configSyncAttempts.appendChild(wrap);
                });
            }

            // Visual Flow Analyzer buttons (one per sync request) + download.
            if (configSyncDownloads) {
                const allAttempts = Array.isArray(summary.attempts) ? summary.attempts : [];
                const flowAttempts = allAttempts.filter((a) => Array.isArray(a.lines) && a.lines.length);

                const attemptHasFailure = (attempt) => {
                    const lines = Array.isArray(attempt.lines) ? attempt.lines : [];
                    if (lines.some((l) => l.type === 'failure')) {
                        return true;
                    }
                    return (Number(attempt.sent) || 0) > 0 && (Number(attempt.success) || 0) === 0;
                };

                const openAttemptFlow = (attemptsForModel, title) => {
                    const model = buildConfigSyncFlowModel(summary, attemptsForModel);
                    if (!model.events.length) {
                        alert('No config sync request/response events were parsed to visualize.');
                        return;
                    }
                    openFlowVisualTab(model, title);
                };

                const makeFlowButton = (labelText, attemptsForModel, title, isError) => {
                    const btn = document.createElement('button');
                    btn.type = 'button';
                    btn.className = isError
                        ? 'inline-flex items-center rounded border border-red-500/60 bg-red-500/10 px-3 py-1.5 text-sm font-bold tracking-wide text-red-200 hover:bg-red-500/20'
                        : 'inline-flex items-center rounded border border-sky-500/60 bg-sky-500/10 px-3 py-1.5 text-sm font-bold tracking-wide text-sky-200 hover:bg-sky-500/20';
                    btn.textContent = labelText;
                    btn.addEventListener('click', () => openAttemptFlow(attemptsForModel, title));
                    return btn;
                };

                if (flowAttempts.length >= 1) {
                    // Combined "all requests" flow button (only when more than one).
                    if (flowAttempts.length > 1) {
                        configSyncDownloads.appendChild(makeFlowButton(
                            `Open Visual Flow Analyzer \u00b7 All ${flowAttempts.length} Requests`,
                            flowAttempts,
                            'Visual Flow Analyzer \u00b7 Configuration Sync \u00b7 All Requests',
                            false,
                        ));
                    }

                    // Compact, scannable table of individual requests (replaces the
                    // long stack of per-request buttons). Shown for one or many.
                    if (configSyncAttempts) {
                        const failedCount = flowAttempts.filter(attemptHasFailure).length;
                        const tableCard = document.createElement('div');
                        tableCard.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-3';

                        const heading = document.createElement('div');
                        heading.className = 'mb-2 flex items-center justify-between';
                        const headingTitle = document.createElement('div');
                        headingTitle.className = 'text-xs font-bold uppercase tracking-wide text-sky-300';
                        headingTitle.textContent = `Config Sync Requests (${flowAttempts.length})`;
                        const headingMeta = document.createElement('div');
                        headingMeta.className = 'text-xs font-semibold';
                        headingMeta.innerHTML = failedCount
                            ? `<span class="text-emerald-600">${flowAttempts.length - failedCount} ok</span> \u00b7 <span class="text-red-600">${failedCount} failed</span>`
                            : `<span class="text-emerald-600">all ${flowAttempts.length} ok</span>`;
                        heading.appendChild(headingTitle);
                        heading.appendChild(headingMeta);
                        tableCard.appendChild(heading);

                        const scroll = document.createElement('div');
                        scroll.className = 'max-h-72 overflow-auto';
                        const table = document.createElement('table');
                        table.className = 'w-full text-left text-sm';
                        table.innerHTML = '<thead><tr class="text-[11px] uppercase tracking-wide text-sky-200/60">'
                            + '<th class="py-1 pr-3 font-semibold">#</th>'
                            + '<th class="py-1 pr-3 font-semibold">Time</th>'
                            + '<th class="py-1 pr-3 font-semibold">Status</th>'
                            + '<th class="py-1 pr-3 font-semibold">Sent / Success</th>'
                            + '<th class="py-1 text-right font-semibold">Flow</th></tr></thead>';
                        const tbody = document.createElement('tbody');

                        flowAttempts.forEach((attempt) => {
                            const isErr = attemptHasFailure(attempt);
                            const firstLine = (Array.isArray(attempt.lines) ? attempt.lines : [])[0] || {};
                            const flowTitle = `Visual Flow Analyzer \u00b7 Config Sync Request ${attempt.index}`;
                            const openThis = () => openAttemptFlow([attempt], flowTitle);

                            const tr = document.createElement('tr');
                            tr.className = isErr
                                ? 'cursor-pointer border-t border-red-500/15 hover:bg-red-500/10'
                                : 'cursor-pointer border-t border-sky-500/10 hover:bg-sky-500/10';
                            tr.addEventListener('click', openThis);

                            const numCell = document.createElement('td');
                            numCell.className = 'py-1.5 pr-3 font-semibold text-sky-100';
                            numCell.textContent = String(attempt.index);

                            const timeCell = document.createElement('td');
                            timeCell.className = 'py-1.5 pr-3 font-mono text-xs text-slate-600';
                            timeCell.textContent = firstLine.timestamp || 'Unknown';

                            const statusCell = document.createElement('td');
                            statusCell.className = 'py-1.5 pr-3';
                            const badge = document.createElement('span');
                            badge.className = isErr
                                ? 'inline-flex items-center rounded-full border border-red-400 bg-red-100 px-2 py-0.5 text-xs font-bold text-red-700'
                                : 'inline-flex items-center rounded-full border border-emerald-400 bg-emerald-100 px-2 py-0.5 text-xs font-bold text-emerald-700';
                            badge.textContent = isErr ? '\u26a0 Failed' : '\u2714 Success';
                            statusCell.appendChild(badge);

                            const countCell = document.createElement('td');
                            countCell.className = 'py-1.5 pr-3 text-xs text-slate-600';
                            countCell.textContent = `${Number(attempt.sent) || 0} / ${Number(attempt.success) || 0}`;

                            const actionCell = document.createElement('td');
                            actionCell.className = 'py-1.5 text-right';
                            const viewBtn = document.createElement('button');
                            viewBtn.type = 'button';
                            viewBtn.className = 'rounded border border-sky-500/50 px-2 py-0.5 text-xs font-bold text-sky-200 hover:bg-sky-500/15';
                            viewBtn.textContent = 'View Flow';
                            viewBtn.addEventListener('click', (e) => {
                                e.stopPropagation();
                                openThis();
                            });
                            actionCell.appendChild(viewBtn);

                            tr.appendChild(numCell);
                            tr.appendChild(timeCell);
                            tr.appendChild(statusCell);
                            tr.appendChild(countCell);
                            tr.appendChild(actionCell);
                            tbody.appendChild(tr);
                        });

                        table.appendChild(tbody);
                        scroll.appendChild(table);
                        tableCard.appendChild(scroll);
                        configSyncAttempts.appendChild(tableCard);
                    }
                }

                if (summary.raw_text) {
                    const clean = stripSuppressedOutputLines(summary.raw_text);
                    if (clean) {
                        const blob = new Blob([clean], { type: 'text/plain;charset=utf-8' });
                        const objectUrl = URL.createObjectURL(blob);
                        configSyncSummaryDownloadUrls.push(objectUrl);
                        const link = document.createElement('a');
                        link.href = objectUrl;
                        link.download = String(summary.download_filename || 'configuration_sync_analysis.log');
                        link.className = 'inline-flex items-center rounded border border-sky-500/50 px-3 py-1.5 text-sm font-bold tracking-wide text-sky-200 hover:bg-sky-500/10';
                        link.textContent = 'Download Configuration Sync Logs';
                        configSyncDownloads.appendChild(link);
                    }
                }
            }

            configSyncSummaryWrap.classList.remove('hidden');
        }

        function resetEventViewerSummary() {
            if (eventViewerSummaryDownloadUrls.length) {
                eventViewerSummaryDownloadUrls.forEach((url) => URL.revokeObjectURL(url));
            }
            eventViewerSummaryDownloadUrls = [];
            if (eventViewerSubtitle) {
                eventViewerSubtitle.textContent = '';
            }
            if (eventViewerTimeRange) {
                eventViewerTimeRange.textContent = '';
            }
            if (eventViewerNote) {
                eventViewerNote.textContent = '';
                eventViewerNote.classList.add('hidden');
            }
            [eventViewerStatCards, eventViewerTopEvents, eventViewerTable, eventViewerDownloads].forEach((el) => {
                if (el) {
                    el.innerHTML = '';
                }
            });
            if (eventViewerSummaryWrap) {
                eventViewerSummaryWrap.classList.add('hidden');
            }
        }

        function resetTndSummary() {
            if (tndOverallStatus) {
                tndOverallStatus.innerHTML = '';
            }
            if (tndFlowCards) {
                tndFlowCards.innerHTML = '';
            }
            if (tndPauseTableWrap) {
                tndPauseTableWrap.innerHTML = '';
                tndPauseTableWrap.classList.add('hidden');
            }
            if (tndWarnings) {
                tndWarnings.innerHTML = '';
                tndWarnings.classList.add('hidden');
            }
            if (tndSummaryWrap) {
                tndSummaryWrap.classList.add('hidden');
            }
        }

        function renderTndSummary(summary) {
            resetTndSummary();
            if (!summary || !tndSummaryWrap || !tndFlowCards) {
                return;
            }

            const flows = Array.isArray(summary.flows) ? summary.flows : [];
            const anyPaused = flows.some((flow) => flow && flow.paused_by_tnd);
            const anyDetected = flows.some((flow) => flow && flow.detected);

            if (tndOverallStatus) {
                const badge = document.createElement('span');
                let badgeClass;
                let badgeText;
                if (anyPaused) {
                    badgeClass = 'inline-flex items-center gap-1 rounded-full border border-emerald-500 bg-emerald-100 px-3 py-0.5 text-sm font-bold text-emerald-700';
                    badgeText = '\u25cf Paused by TND \u2014 Trusted Network Active';
                } else if (anyDetected) {
                    badgeClass = 'inline-flex items-center gap-1 rounded-full border border-sky-500 bg-sky-100 px-3 py-0.5 text-sm font-bold text-sky-700';
                    badgeText = '\u25d1 TND Configured \u2014 Not on Trusted Network';
                } else {
                    badgeClass = 'inline-flex items-center gap-1 rounded-full border border-slate-400 bg-slate-100 px-3 py-0.5 text-sm font-bold text-slate-600';
                    badgeText = '\u25cb TND Not Configured';
                }
                badge.className = badgeClass;
                badge.textContent = badgeText;
                tndOverallStatus.appendChild(badge);
            }

            const runtimeBadgeStyle = (status) => {
                switch (status) {
                    case 'Paused by TND':
                        return 'border-emerald-500 bg-emerald-100 text-emerald-700';
                    case 'Configured (not on trusted network)':
                        return 'border-sky-500 bg-sky-100 text-sky-700';
                    default:
                        return 'border-slate-400 bg-slate-100 text-slate-600';
                }
            };

            const chipList = (label, values, tone) => {
                const wrap = document.createElement('div');
                wrap.className = 'mt-2';
                const head = document.createElement('div');
                head.className = 'mb-1 text-[11px] font-semibold uppercase tracking-wide text-sky-200/60';
                head.textContent = label;
                wrap.appendChild(head);
                if (!values || !values.length) {
                    const none = document.createElement('span');
                    none.className = 'text-xs italic text-slate-500';
                    none.textContent = 'None';
                    wrap.appendChild(none);
                    return wrap;
                }
                const chips = document.createElement('div');
                chips.className = 'flex flex-wrap gap-1.5';
                values.forEach((value) => {
                    const chip = document.createElement('span');
                    chip.className = `inline-flex items-center rounded border px-2 py-0.5 text-xs font-mono ${tone}`;
                    chip.textContent = String(value);
                    chips.appendChild(chip);
                });
                wrap.appendChild(chips);
                return wrap;
            };

            const blockList = (label, values, tone) => {
                const wrap = document.createElement('div');
                wrap.className = 'mt-2';
                const head = document.createElement('div');
                head.className = 'mb-1 text-[11px] font-semibold uppercase tracking-wide text-sky-200/60';
                head.textContent = label;
                wrap.appendChild(head);
                if (!values || !values.length) {
                    const none = document.createElement('span');
                    none.className = 'text-xs italic text-slate-500';
                    none.textContent = 'None';
                    wrap.appendChild(none);
                    return wrap;
                }
                const list = document.createElement('div');
                list.className = 'flex flex-col gap-1.5';
                values.forEach((value) => {
                    const item = document.createElement('div');
                    item.className = `rounded border px-2 py-1 text-xs font-mono leading-relaxed break-all whitespace-normal ${tone}`;
                    item.textContent = String(value);
                    list.appendChild(item);
                });
                wrap.appendChild(list);
                return wrap;
            };

            flows.forEach((flow) => {
                if (!flow) {
                    return;
                }
                const detected = !!flow.detected;
                const card = document.createElement('div');
                card.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-4';

                const header = document.createElement('div');
                header.className = 'flex items-start justify-between gap-2';
                const titleWrap = document.createElement('div');
                const title = document.createElement('div');
                title.className = 'text-sm font-bold text-sky-200';
                title.textContent = `${flow.flow || 'Flow'} \u00b7 ${flow.proxy_config_label || ''}`.trim();
                const subtitle = document.createElement('div');
                subtitle.className = 'text-[11px] font-mono text-slate-500';
                subtitle.textContent = flow.proxy_config_id || '';
                titleWrap.appendChild(title);
                titleWrap.appendChild(subtitle);
                const statusBadge = document.createElement('span');
                statusBadge.className = detected
                    ? 'shrink-0 inline-flex items-center rounded-full border border-emerald-500 bg-emerald-100 px-2.5 py-0.5 text-xs font-bold text-emerald-700'
                    : 'shrink-0 inline-flex items-center rounded-full border border-slate-400 bg-slate-100 px-2.5 py-0.5 text-xs font-bold text-slate-600';
                statusBadge.textContent = detected ? 'Detected' : 'Not Detected';
                header.appendChild(titleWrap);
                header.appendChild(statusBadge);
                card.appendChild(header);

                const runtimeStatus = flow.runtime_status || 'Unknown';
                const runtimeRow = document.createElement('div');
                runtimeRow.className = 'mt-2 flex items-center gap-2';
                const runtimeLabel = document.createElement('span');
                runtimeLabel.className = 'text-[11px] font-semibold uppercase tracking-wide text-sky-200/60';
                runtimeLabel.textContent = 'Runtime (ZTA logs)';
                const runtimeBadge = document.createElement('span');
                runtimeBadge.className = `inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-bold ${runtimeBadgeStyle(runtimeStatus)}`;
                runtimeBadge.textContent = runtimeStatus;
                runtimeRow.appendChild(runtimeLabel);
                runtimeRow.appendChild(runtimeBadge);
                card.appendChild(runtimeRow);

                if (Array.isArray(flow.pause_conditions) && flow.pause_conditions.length) {
                    card.appendChild(blockList('Pause Conditions', flow.pause_conditions, 'border-emerald-300 bg-emerald-50 text-emerald-700'));
                }

                card.appendChild(blockList('Conditional Actions', flow.conditional_actions, 'border-emerald-300 bg-emerald-50 text-emerald-700'));
                card.appendChild(chipList('Network Fingerprints', flow.network_fingerprints, 'border-sky-300 bg-sky-50 text-sky-700'));

                const criteria = document.createElement('div');
                criteria.className = 'mt-3 border-t border-sky-500/15 pt-2';
                const criteriaHead = document.createElement('div');
                criteriaHead.className = 'text-[11px] font-bold uppercase tracking-wide text-sky-300';
                criteriaHead.textContent = 'Matching Criteria';
                criteria.appendChild(criteriaHead);
                criteria.appendChild(chipList('Domains', flow.domains, 'border-slate-300 bg-slate-100 text-slate-600'));
                criteria.appendChild(chipList('DNS Servers', flow.dns_servers, 'border-slate-300 bg-slate-100 text-slate-600'));
                criteria.appendChild(chipList('Trusted Servers', flow.trusted_servers, 'border-slate-300 bg-slate-100 text-slate-600'));
                card.appendChild(criteria);

                tndFlowCards.appendChild(card);
            });

            if (tndPauseTableWrap) {
                const tableCard = document.createElement('div');
                tableCard.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-4';
                const tableHead = document.createElement('div');
                tableHead.className = 'mb-2 text-[11px] font-bold uppercase tracking-wide text-sky-300';
                tableHead.textContent = 'ZTA Pause Status';
                tableCard.appendChild(tableHead);

                const table = document.createElement('table');
                table.className = 'w-full text-left text-xs';
                const thead = document.createElement('thead');
                thead.innerHTML = '<tr class="text-[11px] uppercase tracking-wide text-sky-200/60">'
                    + '<th class="py-1 pr-3 font-semibold">Proxy Config</th>'
                    + '<th class="py-1 pr-3 font-semibold">ZTA Paused by TND</th>'
                    + '<th class="py-1 font-semibold">Time Frame</th>'
                    + '</tr>';
                table.appendChild(thead);

                const tbody = document.createElement('tbody');
                flows.forEach((flow) => {
                    if (!flow) {
                        return;
                    }
                    const paused = !!flow.paused_by_tnd;
                    const tr = document.createElement('tr');
                    tr.className = 'border-t border-sky-500/10';

                    const nameCell = document.createElement('td');
                    nameCell.className = 'py-2 pr-3 font-semibold text-sky-100';
                    nameCell.textContent = `${flow.flow || 'Flow'} \u00b7 ${flow.proxy_config_label || ''}`.trim();
                    tr.appendChild(nameCell);

                    const pausedCell = document.createElement('td');
                    pausedCell.className = 'py-2 pr-3';
                    const pausedBadge = document.createElement('span');
                    pausedBadge.className = paused
                        ? 'inline-flex items-center rounded-full border border-emerald-500 bg-emerald-100 px-2 py-0.5 text-[11px] font-bold text-emerald-700'
                        : 'inline-flex items-center rounded-full border border-slate-400 bg-slate-100 px-2 py-0.5 text-[11px] font-bold text-slate-600';
                    pausedBadge.textContent = paused ? 'Yes' : 'No';
                    pausedCell.appendChild(pausedBadge);
                    tr.appendChild(pausedCell);

                    const timeCell = document.createElement('td');
                    timeCell.className = 'py-2 font-mono text-slate-300';
                    if (paused) {
                        const start = flow.pause_start || '';
                        const end = flow.pause_end || '';
                        timeCell.textContent = start && end && start !== end ? `${start} \u2192 ${end}` : (start || end || '\u2014');
                    } else {
                        timeCell.textContent = '\u2014';
                    }
                    tr.appendChild(timeCell);

                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                tableCard.appendChild(table);
                tndPauseTableWrap.appendChild(tableCard);
                tndPauseTableWrap.classList.remove('hidden');
            }

            const warnings = Array.isArray(summary.parse_warnings) ? summary.parse_warnings : [];
            if (warnings.length && tndWarnings) {
                tndWarnings.textContent = `Parse warnings: ${warnings.join(' | ')}`;
                tndWarnings.classList.remove('hidden');
            }

            tndSummaryWrap.classList.remove('hidden');
        }


        const uztnaSummaryWrap = document.getElementById('uztnaSummaryWrap');
        const uztnaOptions = document.getElementById('uztnaOptions');
        const uztnaFlowFilterInput = document.getElementById('uztnaFlowFilterInput');
        const uztnaSummarySub = document.getElementById('uztnaSummarySub');
        const uztnaSummaryHeadline = document.getElementById('uztnaSummaryHeadline');
        const uztnaSummaryVerdict = document.getElementById('uztnaSummaryVerdict');
        const uztnaSummaryCards = document.getElementById('uztnaSummaryCards');
        const uztnaSummaryLadders = document.getElementById('uztnaSummaryLadders');

        const UZTNA_STAGE_GLYPH = { ok: '✓', fail: '✕', blocked: '⊘', unknown: '?' };

        function uztnaAppendTextWithLinks(parent, text) {
            const pattern = /(https?:\/\/[^\s)]+)/g;
            let last = 0;
            String(text || '').replace(pattern, function (url, _m, offset) {
                if (offset > last) { parent.appendChild(document.createTextNode(text.slice(last, offset))); }
                const a = document.createElement('a');
                a.href = url; a.textContent = url; a.target = '_blank'; a.rel = 'noopener';
                a.className = 'dh-suggest-link';
                parent.appendChild(a);
                last = offset + url.length;
                return url;
            });
            if (last < String(text || '').length) { parent.appendChild(document.createTextNode(text.slice(last))); }
        }

        function resetUztnaSummary() {
            [uztnaSummarySub, uztnaSummaryHeadline, uztnaSummaryVerdict, uztnaSummaryCards, uztnaSummaryLadders]
                .forEach(function (node) { if (node) { node.innerHTML = ''; } });
            if (uztnaSummaryWrap) {
                uztnaSummaryWrap.classList.add('hidden');
            }
        }

        // Flows that fail the same way at the same stage tell one story, so they are
        // grouped by outcome signature rather than listed one row per flow.
        // Mirrors the standalone analyzer's behaviour: selecting a step in the SVG
        // highlights the log line that produced it.
        function attachUztnaSequenceInteraction(seqEl, model, container) {
            const events = model.events || [];
            const log = model.logLines || [];
            if (!log.length) { return; }

            const detail = document.createElement('div');
            detail.className = 'dh-seq-detail';
            detail.textContent = 'Click any step above to highlight the log line that produced it.';
            container.appendChild(detail);

            const box = document.createElement('div');
            box.className = 'dh-seq-log';
            log.forEach(function (line, i) {
                const ln = document.createElement('div');
                ln.className = 'ln';
                ln.dataset.i = String(i);
                ln.textContent = line;
                box.appendChild(ln);
            });
            container.appendChild(box);

            const lineEls = box.querySelectorAll('.ln');
            const rows = seqEl.querySelectorAll('.fa-row');
            rows.forEach(function (row) {
                row.addEventListener('click', function () {
                    const idx = parseInt(row.getAttribute('data-idx'), 10);
                    const ev = events[idx];
                    if (!ev) { return; }
                    rows.forEach(function (r) { r.classList.remove('sel'); });
                    row.classList.add('sel');
                    lineEls.forEach(function (l) { l.classList.remove('hl', 'hlerr'); });
                    detail.innerHTML = '<span class="dl"></span><span class="ts"></span>';
                    detail.querySelector('.dl').textContent = ev.label;
                    detail.querySelector('.ts').textContent = ev.timestamp ? '  ' + ev.timestamp : '';
                    const li = typeof ev.logIndex === 'number' ? ev.logIndex : -1;
                    if (li >= 0 && lineEls[li]) {
                        lineEls[li].classList.add(ev.error ? 'hlerr' : 'hl');
                        box.scrollTop = lineEls[li].offsetTop - box.clientHeight / 2 + lineEls[li].clientHeight / 2;
                    }
                });
            });
        }

        function buildUztnaStripLegend() {
            const legend = document.createElement('div');
            legend.className = 'dh-legend';
            [
                ['ok', '\u2713', 'Stage completed'],
                ['fail', '\u2715', 'Stage failed \u2014 the flow stopped here'],
                ['blocked', '\u2298', 'Never ran \u2014 blocked by the failure above'],
                ['unknown', '?', 'Not recorded in the log'],
            ].forEach(function (item) {
                const row = document.createElement('span');
                row.className = 'dh-legend-item';
                const dot = document.createElement('span');
                dot.className = 'dh-strip-dot is-' + item[0];
                dot.textContent = item[1];
                row.appendChild(dot);
                const txt = document.createElement('span');
                txt.textContent = item[2];
                row.appendChild(txt);
                legend.appendChild(row);
            });
            return legend;
        }

        function buildUztnaSequenceLegend(model) {
            const legend = document.createElement('div');
            legend.className = 'dh-legend dh-legend-seq';
            const client = model.clientLabel || 'Client';
            const peer = model.proxyLabel || 'Peer';
            [
                ['o', '\u2192', client + ' \u2192 ' + peer + ' (request / setup)'],
                ['i', '\u2190', peer + ' \u2192 ' + client + ' (response / connected)'],
                ['s', '\u21ba', 'Client-side processing \u2014 nothing left the endpoint'],
                ['e', '\u26a0', 'Error / failure'],
            ].forEach(function (item) {
                const row = document.createElement('span');
                row.className = 'dh-legend-item';
                const glyph = document.createElement('span');
                glyph.className = 'dh-legend-glyph is-' + item[0];
                glyph.textContent = item[1];
                row.appendChild(glyph);
                const txt = document.createElement('span');
                txt.textContent = item[2];
                row.appendChild(txt);
                legend.appendChild(row);
            });
            return legend;
        }

        function groupUztnaEpisodes(episodes) {
            const groups = [];
            const byKey = {};
            episodes.forEach(function (ep) {
                const statuses = (ep.ladder || []).map(function (s) { return s.status; }).join('');
                const key = (ep.resource || '?') + '|' + statuses + '|' + (ep.tls_error || '');
                if (!byKey[key]) {
                    byKey[key] = {
                        key: key,
                        resource: ep.resource || 'unknown',
                        ladder: ep.ladder || [],
                        tlsError: ep.tls_error || '',
                        failedStage: (ep.ladder || []).find(function (s) { return s.status === 'fail'; }),
                        episodes: [],
                    };
                    groups.push(byKey[key]);
                }
                byKey[key].episodes.push(ep);
            });
            groups.sort(function (a, b) { return b.episodes.length - a.episodes.length; });
            return groups;
        }

        function buildUztnaStageStrip(ladder) {
            const strip = document.createElement('span');
            strip.className = 'dh-strip';
            (ladder || []).forEach(function (stage, i) {
                if (i) {
                    const link = document.createElement('span');
                    link.className = 'dh-strip-link';
                    strip.appendChild(link);
                }
                const dot = document.createElement('span');
                dot.className = 'dh-strip-dot is-' + stage.status;
                dot.title = stage.name + ' — ' + stage.detail;
                dot.textContent = UZTNA_STAGE_GLYPH[stage.status] || '?';
                strip.appendChild(dot);
            });
            return strip;
        }

        function buildUztnaGroup(group, index) {
            const wrap = document.createElement('details');
            wrap.className = 'dh-grp';
            if (index === 0) { wrap.open = true; }

            const failed = !!group.failedStage;
            const n = group.episodes.length;
            const head = document.createElement('summary');
            head.className = 'dh-grp-head';

            const dot = document.createElement('span');
            dot.className = 'dh-ladder-dot ' + (failed ? 'is-fail' : 'is-ok');
            head.appendChild(dot);

            const title = document.createElement('span');
            title.className = 'dh-grp-title';
            title.textContent = group.resource;
            head.appendChild(title);

            head.appendChild(buildUztnaStageStrip(group.ladder));

            const verdict = document.createElement('span');
            verdict.className = 'dh-grp-verdict' + (failed ? ' is-fail' : '');
            verdict.textContent = failed
                ? n + (n === 1 ? ' flow' : ' flows') + ' stopped at ' + group.failedStage.name
                    + (group.tlsError ? ' (' + group.tlsError + ')' : '')
                : n + (n === 1 ? ' flow' : ' flows') + ' completed the client-side stages';
            head.appendChild(verdict);
            wrap.appendChild(head);

            const body = document.createElement('div');
            body.className = 'dh-grp-body';

            const stagesCap = document.createElement('div');
            stagesCap.className = 'dh-grp-caption';
            stagesCap.textContent = 'Stage summary';
            body.appendChild(stagesCap);

            const rungs = document.createElement('div');
            rungs.className = 'dh-ladder-rungs';
            (group.ladder || []).forEach(function (stage) {
                const row = document.createElement('div');
                row.className = 'dh-rung is-' + stage.status;
                row.innerHTML = '<span class="dh-rung-mark">' + (UZTNA_STAGE_GLYPH[stage.status] || '?') + '</span>'
                    + '<span class="dh-rung-name">' + stage.name + '</span>'
                    + '<span class="dh-rung-actor">' + (stage.actor || '') + '</span>'
                    + '<span class="dh-rung-detail">' + stage.detail + '</span>';
                rungs.appendChild(row);
            });
            body.appendChild(rungs);

            const utils = window.DarthawkFlowUtils;
            const rep = group.episodes[0];
            const model = utils && typeof utils.buildUztnaFlowModel === 'function' && (rep.lines || []).length
                ? utils.buildUztnaFlowModel(rep)
                : null;

            if (model && model.events && model.events.length) {
                const cap = document.createElement('div');
                cap.className = 'dh-grp-caption';
                cap.textContent = n === 1
                    ? 'Sequence for srcPort ' + (rep.src_port || '?')
                    : 'Sequence for srcPort ' + (rep.src_port || '?') + ' — representative of all ' + n + ' flows below';
                body.appendChild(cap);
                // The sequence view carries its own dark palette, so it needs a dark
                // surface to stay legible under either theme.
                const seq = document.createElement('div');
                seq.className = 'dh-seq';
                seq.innerHTML = renderFlowSequenceSvg(model);
                body.appendChild(seq);
                body.appendChild(buildUztnaSequenceLegend(model));
                attachUztnaSequenceInteraction(seq, model, body);
            }

            const portsLabel = document.createElement('div');
            portsLabel.className = 'dh-grp-caption';
            portsLabel.textContent = 'Affected flows (' + n + ') — open one for its own sequence and log drill-down';
            body.appendChild(portsLabel);

            const ports = document.createElement('div');
            ports.className = 'dh-ports';
            group.episodes.slice(0, 60).forEach(function (ep) {
                const chip = document.createElement('button');
                chip.type = 'button';
                chip.className = 'dh-port-chip';
                chip.innerHTML = '<span class="dh-port-num">' + (ep.src_port || '?') + '</span>'
                    + '<span class="dh-port-meta">' + (ep.process || '') + ' · '
                    + (ep.start ? ep.start.slice(11, 19) : '') + '</span>';
                chip.addEventListener('click', function () {
                    const m = utils && utils.buildUztnaFlowModel ? utils.buildUztnaFlowModel(ep) : null;
                    if (m) {
                        openFlowVisualTab(m, 'Visual Flow Analyzer · Universal ZTNA · '
                            + (ep.resource || 'flow') + ' · srcPort ' + (ep.src_port || '?'));
                    }
                });
                ports.appendChild(chip);
            });
            body.appendChild(ports);
            if (n > 60) {
                const more = document.createElement('p');
                more.className = 'dh-ladder-note';
                more.textContent = 'Showing the first 60 of ' + n + ' flows in this group.';
                body.appendChild(more);
            }

            wrap.appendChild(body);
            return wrap;
        }

        function buildUztnaLadder(episode, index) {
            const wrap = document.createElement('details');
            wrap.className = 'dh-ladder';
            if (index === 0) { wrap.open = true; }

            const summary = document.createElement('summary');
            summary.className = 'dh-ladder-summary';
            const failed = (episode.ladder || []).some(function (s) { return s.status === 'fail'; });
            summary.innerHTML = '<span class="dh-ladder-dot ' + (failed ? 'is-fail' : 'is-ok') + '"></span>'
                + '<span class="dh-ladder-title">' + (episode.resource || 'unknown resource') + '</span>'
                + '<span class="dh-ladder-meta">srcPort ' + (episode.src_port || '?')
                + (episode.process ? ' · ' + episode.process : '')
                + (episode.start ? ' · ' + episode.start.slice(11, 19) : '') + '</span>';
            wrap.appendChild(summary);

            const rungs = document.createElement('div');
            rungs.className = 'dh-ladder-rungs';
            (episode.ladder || []).forEach(function (stage) {
                const row = document.createElement('div');
                row.className = 'dh-rung is-' + stage.status;
                row.innerHTML = '<span class="dh-rung-mark">' + (UZTNA_STAGE_GLYPH[stage.status] || '?') + '</span>'
                    + '<span class="dh-rung-name">' + stage.name + '</span>'
                    + '<span class="dh-rung-actor">' + (stage.actor || '') + '</span>'
                    + '<span class="dh-rung-detail">' + stage.detail + '</span>';
                rungs.appendChild(row);
            });

            wrap.appendChild(rungs);
            return wrap;
        }

        function renderUztnaSummary(summary) {
            resetUztnaSummary();
            if (!summary || !uztnaSummaryWrap || !summary.available) {
                if (summary && uztnaSummaryWrap && summary.reason) {
                    uztnaSummaryVerdict.innerHTML = '<div class="dh-snap-verdict"><div class="dh-snap-verdict-summary">'
                        + summary.reason + '</div></div>';
                    uztnaSummaryWrap.classList.remove('hidden');
                }
                return;
            }

            const verdict = summary.verdict || {};
            uztnaSummaryVerdict.innerHTML = '<div class="dh-snap-verdict is-' + (verdict.level || 'unknown') + '">'
                + '<div class="dh-snap-verdict-title">' + (verdict.level === 'problem' ? '✕ Local enforcement failing'
                    : verdict.level === 'healthy' ? '✓ Local enforcement healthy' : 'ℹ No Universal ZTNA activity') + '</div>'
                + '<div class="dh-snap-verdict-summary">' + (verdict.summary || '') + '</div></div>';

            if (summary.enforcement_points && summary.enforcement_points.length) {
                uztnaSummarySub.textContent = 'Local enforcement point: ' + summary.enforcement_points.join(', ');
            }
            const flt = summary.filter;
            if (flt && flt.term) {
                const note = document.createElement('div');
                note.className = 'dh-chip is-info';
                note.textContent = 'Filtered by “' + flt.term + '” — ' + flt.matched + ' of ' + flt.total + ' redirected flows';
                uztnaSummaryVerdict.appendChild(note);
            }
            if (summary.episode_count) {
                uztnaSummaryHeadline.textContent = summary.abandoned_count
                    ? summary.abandoned_count + ' of ' + summary.episode_count + ' redirects abandoned'
                    : summary.episode_count + ' redirects';
            }

            (summary.assessment || []).forEach(function (card) {
                const box = document.createElement('div');
                box.className = 'dh-issue sev-' + (card.severity === 'critical' ? 'critical'
                    : card.severity === 'warning' ? 'warning' : 'info');
                let html = '<div class="dh-issue-head"><span class="dh-issue-title">' + card.label + '</span>'
                    + '<span class="dh-issue-badge">' + (card.chip || '') + '</span></div>'
                    + '<div class="dh-issue-summary">' + (card.summary || '') + '</div>';
                if (card.meaning) {
                    html += '<div class="dh-issue-block"><div class="dh-issue-block-label">What it means</div>'
                        + '<div class="dh-issue-block-body">' + card.meaning + '</div></div>';
                }
                if (card.impact) {
                    html += '<div class="dh-issue-block"><div class="dh-issue-block-label">Impact</div>'
                        + '<div class="dh-issue-block-body">' + card.impact + '</div></div>';
                }
                if (card.metric) {
                    html += '<div class="dh-issue-metric">' + card.metric + '</div>';
                }
                box.innerHTML = html;

                if (card.groups && card.groups.length && card.group_kind !== 'resource') {
                    const evidence = document.createElement('div');
                    evidence.className = 'dh-issue-block';
                    evidence.innerHTML = '<div class="dh-issue-block-label">What the logs show</div>';
                    const list = document.createElement('div');
                    list.className = 'dh-evlist';
                    card.groups.forEach(function (group) {
                        const row = document.createElement('div');
                        row.className = 'dh-evrow';
                        row.innerHTML = '<span class="dh-evrow-text">' + group.label + '</span>'
                            + '<span class="dh-evrow-count">' + group.count + '×</span>';
                        list.appendChild(row);
                    });
                    evidence.appendChild(list);
                    box.appendChild(evidence);
                }

                if (card.chain && card.chain.length) {
                    const chain = document.createElement('div');
                    chain.className = 'dh-certchain';
                    chain.innerHTML = '<div class="dh-issue-block-label">Certificate chain presented</div>';
                    card.chain.forEach(function (link, i) {
                        const row = document.createElement('div');
                        row.className = 'dh-certlink';
                        row.innerHTML = '<span class="dh-certlink-idx">' + (i === 0 ? 'leaf' : i) + '</span>'
                            + '<code>' + link.subject + '</code>'
                            + '<span class="dh-certlink-by">issued by</span><code>' + link.issuer + '</code>';
                        chain.appendChild(row);
                    });
                    box.appendChild(chain);
                }

                if (card.suggestions && card.suggestions.length) {
                    const sugg = document.createElement('div');
                    sugg.className = 'dh-suggest';
                    sugg.innerHTML = '<div class="dh-suggest-label">Suggested next steps</div>';
                    const list = document.createElement('ul');
                    card.suggestions.forEach(function (item) {
                        const li = document.createElement('li');
                        uztnaAppendTextWithLinks(li, item);
                        list.appendChild(li);
                    });
                    sugg.appendChild(list);
                    box.appendChild(sugg);
                }
                uztnaSummaryCards.appendChild(box);
            });

            const episodes = summary.episodes || [];
            if (episodes.length) {
                const groups = groupUztnaEpisodes(episodes);
                const head = document.createElement('div');
                head.className = 'dh-snap-section';
                head.textContent = 'Connection ladder — ' + episodes.length + ' redirect'
                    + (episodes.length === 1 ? '' : 's') + ' in ' + groups.length
                    + ' outcome' + (groups.length === 1 ? '' : 's');
                uztnaSummaryLadders.appendChild(head);
                const note = document.createElement('p');
                note.className = 'dh-ladder-note';
                note.textContent = 'Flows that fail the same way at the same stage are grouped together. '
                    + 'Firewall-side enforcement is not visible in a DART bundle.';
                uztnaSummaryLadders.appendChild(note);
                uztnaSummaryLadders.appendChild(buildUztnaStripLegend());
                groups.forEach(function (group, i) {
                    uztnaSummaryLadders.appendChild(buildUztnaGroup(group, i));
                });
            }

            uztnaSummaryWrap.classList.remove('hidden');
        }

        function resetUserPauseSummary() {
            if (userPauseOverallStatus) {
                userPauseOverallStatus.innerHTML = '';
            }
            if (userPauseFlowCards) {
                userPauseFlowCards.innerHTML = '';
            }
            if (userPausePauseTableWrap) {
                userPausePauseTableWrap.innerHTML = '';
                userPausePauseTableWrap.classList.add('hidden');
            }
            if (userPauseWarnings) {
                userPauseWarnings.innerHTML = '';
                userPauseWarnings.classList.add('hidden');
            }
            if (userPauseSummaryWrap) {
                userPauseSummaryWrap.classList.add('hidden');
            }
        }

        function renderUserPauseSummary(summary) {
            resetUserPauseSummary();
            if (!summary || !userPauseSummaryWrap || !userPauseFlowCards) {
                return;
            }

            const flows = Array.isArray(summary.flows) ? summary.flows : [];
            const anyPaused = flows.some((flow) => flow && flow.paused_by_user);
            const anyConfigured = flows.some((flow) => flow && flow.config_found);

            if (userPauseOverallStatus) {
                const badge = document.createElement('span');
                let badgeClass;
                let badgeText;
                if (anyPaused) {
                    badgeClass = 'inline-flex items-center gap-1 rounded-full border border-emerald-500 bg-emerald-100 px-3 py-0.5 text-sm font-bold text-emerald-700';
                    badgeText = '\u25cf Paused by User';
                } else if (anyConfigured) {
                    badgeClass = 'inline-flex items-center gap-1 rounded-full border border-sky-500 bg-sky-100 px-3 py-0.5 text-sm font-bold text-sky-700';
                    badgeText = '\u25d1 User Pause Configured \u2014 Not Paused';
                } else {
                    badgeClass = 'inline-flex items-center gap-1 rounded-full border border-slate-400 bg-slate-100 px-3 py-0.5 text-sm font-bold text-slate-600';
                    badgeText = '\u25cb User Pause Not Configured';
                }
                badge.className = badgeClass;
                badge.textContent = badgeText;
                userPauseOverallStatus.appendChild(badge);
            }

            const runtimeBadgeStyle = (status) => {
                switch (status) {
                    case 'Paused by User':
                        return 'border-emerald-500 bg-emerald-100 text-emerald-700';
                    case 'Pause Requested':
                        return 'border-amber-400 bg-amber-100 text-amber-700';
                    case 'Not Paused':
                        return 'border-sky-500 bg-sky-100 text-sky-700';
                    default:
                        return 'border-slate-400 bg-slate-100 text-slate-600';
                }
            };

            const detailRow = (label, value, tone) => {
                const wrap = document.createElement('div');
                wrap.className = 'mt-2 flex items-center justify-between gap-2';
                const head = document.createElement('span');
                head.className = 'text-[11px] font-semibold uppercase tracking-wide text-sky-200/60';
                head.textContent = label;
                const val = document.createElement('span');
                val.className = `text-xs font-mono ${tone || 'text-sky-100'}`;
                val.textContent = String(value);
                wrap.appendChild(head);
                wrap.appendChild(val);
                return wrap;
            };

            flows.forEach((flow) => {
                if (!flow) {
                    return;
                }
                const configured = !!flow.config_found;
                const card = document.createElement('div');
                card.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-4';

                const header = document.createElement('div');
                header.className = 'flex items-start justify-between gap-2';
                const titleWrap = document.createElement('div');
                const title = document.createElement('div');
                title.className = 'text-sm font-bold text-sky-200';
                title.textContent = `${flow.flow || 'Flow'} \u00b7 ${flow.proxy_config_label || ''}`.trim();
                titleWrap.appendChild(title);
                const statusBadge = document.createElement('span');
                statusBadge.className = configured
                    ? 'shrink-0 inline-flex items-center rounded-full border border-emerald-500 bg-emerald-100 px-2.5 py-0.5 text-xs font-bold text-emerald-700'
                    : 'shrink-0 inline-flex items-center rounded-full border border-slate-400 bg-slate-100 px-2.5 py-0.5 text-xs font-bold text-slate-600';
                statusBadge.textContent = configured ? 'Configured' : 'Not Configured';
                header.appendChild(titleWrap);
                header.appendChild(statusBadge);
                card.appendChild(header);

                const runtimeStatus = flow.runtime_status || 'Unknown';
                const runtimeRow = document.createElement('div');
                runtimeRow.className = 'mt-2 flex items-center gap-2';
                const runtimeLabel = document.createElement('span');
                runtimeLabel.className = 'text-[11px] font-semibold uppercase tracking-wide text-sky-200/60';
                runtimeLabel.textContent = 'Runtime (ZTA logs)';
                const runtimeBadge = document.createElement('span');
                runtimeBadge.className = `inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-bold ${runtimeBadgeStyle(runtimeStatus)}`;
                runtimeBadge.textContent = runtimeStatus;
                runtimeRow.appendChild(runtimeLabel);
                runtimeRow.appendChild(runtimeBadge);
                card.appendChild(runtimeRow);

                const config = document.createElement('div');
                config.className = 'mt-3 border-t border-sky-500/15 pt-2';
                const configHead = document.createElement('div');
                configHead.className = 'text-[11px] font-bold uppercase tracking-wide text-sky-300';
                configHead.textContent = 'Pause Configuration';
                config.appendChild(configHead);
                if (configured) {
                    config.appendChild(detailRow('Label', flow.pause_config_label || '\u2014'));
                    config.appendChild(detailRow('Config ID', flow.pause_config_id || '\u2014'));
                    const resumeTimeout = (flow.resume_timeout === null || flow.resume_timeout === undefined || flow.resume_timeout === '')
                        ? 'Unknown'
                        : `${flow.resume_timeout} s`;
                    config.appendChild(detailRow('Resume Timeout', resumeTimeout, 'text-emerald-300'));
                } else {
                    const none = document.createElement('div');
                    none.className = 'mt-2 text-xs italic text-slate-500';
                    none.textContent = 'No user_pause_configs entry for this proxy config.';
                    config.appendChild(none);
                }
                card.appendChild(config);

                if (flow.paused_by_user || flow.pause_requested || flow.max_duration_seconds != null || flow.pause_result) {
                    const runtime = document.createElement('div');
                    runtime.className = 'mt-3 border-t border-sky-500/15 pt-2';
                    const runtimeHead = document.createElement('div');
                    runtimeHead.className = 'text-[11px] font-bold uppercase tracking-wide text-sky-300';
                    runtimeHead.textContent = 'Runtime Pause Details';
                    runtime.appendChild(runtimeHead);
                    if (flow.max_duration_seconds != null) {
                        runtime.appendChild(detailRow('Max Duration', `${flow.max_duration_seconds} s`, 'text-emerald-300'));
                    }
                    if (flow.pause_result) {
                        const tone = String(flow.pause_result).toLowerCase() === 'success' ? 'text-emerald-300' : 'text-amber-300';
                        runtime.appendChild(detailRow('Pause Result', flow.pause_result, tone));
                    }
                    if (flow.enrollment_id) {
                        runtime.appendChild(detailRow('Enrollment ID', flow.enrollment_id));
                    }
                    if (flow.paused_by_user) {
                        const start = flow.pause_start || '';
                        const end = flow.pause_end || '';
                        const timeText = start && end && start !== end ? `${start} \u2192 ${end}` : (start || end || '\u2014');
                        runtime.appendChild(detailRow('Pause Time', timeText, 'text-slate-300'));
                    }
                    card.appendChild(runtime);
                }

                userPauseFlowCards.appendChild(card);
            });

            if (userPausePauseTableWrap) {
                const tableCard = document.createElement('div');
                tableCard.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-4';
                const tableHead = document.createElement('div');
                tableHead.className = 'mb-2 text-[11px] font-bold uppercase tracking-wide text-sky-300';
                tableHead.textContent = 'ZTA Pause Status';
                tableCard.appendChild(tableHead);

                const table = document.createElement('table');
                table.className = 'w-full text-left text-xs';
                const thead = document.createElement('thead');
                thead.innerHTML = '<tr class="text-[11px] uppercase tracking-wide text-sky-200/60">'
                    + '<th class="py-1 pr-3 font-semibold">Proxy Config</th>'
                    + '<th class="py-1 pr-3 font-semibold">Paused by User</th>'
                    + '<th class="py-1 pr-3 font-semibold">Resume Timeout</th>'
                    + '<th class="py-1 font-semibold">Time Frame</th>'
                    + '</tr>';
                table.appendChild(thead);

                const tbody = document.createElement('tbody');
                flows.forEach((flow) => {
                    if (!flow) {
                        return;
                    }
                    const paused = !!flow.paused_by_user;
                    const tr = document.createElement('tr');
                    tr.className = 'border-t border-sky-500/10';

                    const nameCell = document.createElement('td');
                    nameCell.className = 'py-2 pr-3 font-semibold text-sky-100';
                    nameCell.textContent = `${flow.flow || 'Flow'} \u00b7 ${flow.proxy_config_label || ''}`.trim();
                    tr.appendChild(nameCell);

                    const pausedCell = document.createElement('td');
                    pausedCell.className = 'py-2 pr-3';
                    const pausedBadge = document.createElement('span');
                    pausedBadge.className = paused
                        ? 'inline-flex items-center rounded-full border border-emerald-500 bg-emerald-100 px-2 py-0.5 text-[11px] font-bold text-emerald-700'
                        : 'inline-flex items-center rounded-full border border-slate-400 bg-slate-100 px-2 py-0.5 text-[11px] font-bold text-slate-600';
                    pausedBadge.textContent = paused ? 'Yes' : 'No';
                    pausedCell.appendChild(pausedBadge);
                    tr.appendChild(pausedCell);

                    const timeoutCell = document.createElement('td');
                    timeoutCell.className = 'py-2 pr-3 font-mono text-slate-300';
                    timeoutCell.textContent = (flow.resume_timeout === null || flow.resume_timeout === undefined || flow.resume_timeout === '')
                        ? '\u2014'
                        : `${flow.resume_timeout} s`;
                    tr.appendChild(timeoutCell);

                    const timeCell = document.createElement('td');
                    timeCell.className = 'py-2 font-mono text-slate-300';
                    if (paused) {
                        const start = flow.pause_start || '';
                        const end = flow.pause_end || '';
                        timeCell.textContent = start && end && start !== end ? `${start} \u2192 ${end}` : (start || end || '\u2014');
                    } else {
                        timeCell.textContent = '\u2014';
                    }
                    tr.appendChild(timeCell);

                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                tableCard.appendChild(table);
                userPausePauseTableWrap.appendChild(tableCard);
                userPausePauseTableWrap.classList.remove('hidden');
            }

            const warnings = Array.isArray(summary.parse_warnings) ? summary.parse_warnings : [];
            if (warnings.length && userPauseWarnings) {
                userPauseWarnings.textContent = `Parse warnings: ${warnings.join(' | ')}`;
                userPauseWarnings.classList.remove('hidden');
            }

            userPauseSummaryWrap.classList.remove('hidden');
        }


        const EVENT_VIEWER_SEVERITY_STYLE = {
            Error: { badge: 'border-red-400 bg-red-100 text-red-700', node: '#f87171', text: '#fca5a5', isErr: true },
            Critical: { badge: 'border-rose-500 bg-rose-100 text-rose-700', node: '#e11d48', text: '#fda4af', isErr: true },
            Warning: { badge: 'border-amber-400 bg-amber-100 text-amber-700', node: '#f59e0b', text: '#fcd34d', isErr: false },
            Information: { badge: 'border-sky-400 bg-sky-100 text-sky-700', node: '#38bdf8', text: '#7dd3fc', isErr: false },
            Verbose: { badge: 'border-slate-300 bg-slate-100 text-slate-600', node: '#94a3b8', text: '#cbd5e1', isErr: false },
            Unknown: { badge: 'border-slate-300 bg-slate-100 text-slate-600', node: '#94a3b8', text: '#cbd5e1', isErr: false },
        };

        function buildEventViewerFlowModel(summary, eventsOverride) {
            const channelOrder = Array.isArray(summary.channel_order) && summary.channel_order.length
                ? summary.channel_order
                : ['Application', 'System', 'ZTA'];
            const rawEvents = Array.isArray(eventsOverride)
                ? eventsOverride
                : (Array.isArray(summary.events) ? summary.events : []);
            const events = [];
            const logLines = [];

            rawEvents.forEach((ev, i) => {
                const severity = String(ev.severity || '').trim() || 'Warning';
                const channel = String(ev.channel || 'System').trim();
                const provider = String(ev.provider || 'Unknown').trim();
                const eventId = ev.event_id != null ? ev.event_id : 0;
                const message = String(ev.message || '').trim();
                const source = String(ev.source || '').trim();
                const style = EVENT_VIEWER_SEVERITY_STYLE[severity] || EVENT_VIEWER_SEVERITY_STYLE.Warning;
                logLines.push(`${severity} \u00b7 ${channel} [${ev.timestamp || 'Unknown'}] (Provider: ${provider}, Event ID: ${eventId}${source ? ', Source: ' + source : ''}) ${message}`);
                events.push({
                    label: `${severity} \u2014 ${channel} \u00b7 ${provider} (ID ${eventId})`,
                    timestamp: ev.timestamp || '',
                    raw: message || `${severity} event on ${channel} (Provider: ${provider}, Event ID: ${eventId})`,
                    logIndex: i,
                    error: !!style.isErr,
                    channel,
                    severity,
                    provider,
                    eventId,
                });
            });

            const activeChannels = Array.isArray(eventsOverride)
                ? channelOrder.filter((ch) => rawEvents.some((ev) => String(ev.channel || 'System').trim() === ch))
                : channelOrder;
            const lanes = activeChannels.length ? activeChannels : channelOrder;

            const files = summary.files || {};
            const sevTotals = { Error: 0, Critical: 0, Warning: 0 };
            events.forEach((ev) => {
                if (sevTotals[ev.severity] != null) {
                    sevTotals[ev.severity] += 1;
                }
            });
            const scopeLabel = Array.isArray(eventsOverride) && lanes.length === 1 ? `${lanes[0]} \u00b7 ` : '';
            const summaryBits = [
                `Time Range: ${summary.time_range_display || 'unavailable'}`,
                `EVTX Files: Application ${files.application || 0} \u00b7 System ${files.system || 0} \u00b7 ZTA ${files.zta || 0}`,
                `Events Shown: ${events.length}`,
                `Error: ${sevTotals.Error} \u00b7 Critical: ${sevTotals.Critical} \u00b7 Warning: ${sevTotals.Warning}`,
            ];

            return {
                lanes,
                events,
                logLines,
                summaryBits,
                title: `Visual Flow Analyzer \u00b7 ${scopeLabel}Event Viewer Logs`,
            };
        }

        function renderEventViewerSwimlaneSvg(model) {
            const lanes = (model.lanes && model.lanes.length ? model.lanes : ['Application', 'System', 'ZTA']);
            const events = model.events || [];
            const marginLeft = 210;
            const laneW = 280;
            const laneGap = 24;
            const topY = 34;
            const headerH = 44;
            const eventsTop = topY + headerH + 40;
            const rowH = 70;
            const width = marginLeft + lanes.length * laneW + (lanes.length - 1) * laneGap + 40;
            const height = eventsTop + Math.max(events.length, 1) * rowH + 30;
            const laneCenter = (idx) => marginLeft + idx * (laneW + laneGap) + laneW / 2;
            const laneColors = ['#38bdf8', '#a78bfa', '#34d399'];
            const parts = [];

            parts.push('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + width + ' ' + height + '" width="100%" style="min-width:' + Math.min(width, 1100) + 'px">');

            // Lane headers + vertical guide lines.
            lanes.forEach((lane, idx) => {
                const cx = laneCenter(idx);
                const color = laneColors[idx % laneColors.length];
                const x = cx - laneW / 2;
                parts.push('<line x1="' + cx + '" y1="' + (topY + headerH) + '" x2="' + cx + '" y2="' + (height - 16) + '" stroke="#334155" stroke-width="2" stroke-dasharray="4 6"/>');
                parts.push('<rect x="' + x + '" y="' + topY + '" width="' + laneW + '" height="' + headerH + '" rx="9" fill="rgba(30,41,59,0.65)" stroke="' + color + '" stroke-width="1.6"/>');
                parts.push('<text x="' + cx + '" y="' + (topY + 28) + '" text-anchor="middle" fill="#e2e8f0" font-size="14" font-weight="700" font-family="monospace">' + escapeHtml(lane) + '</text>');
            });

            if (!events.length) {
                parts.push('<text x="' + (width / 2) + '" y="' + (eventsTop + 30) + '" text-anchor="middle" fill="#94a3b8" font-size="13" font-family="monospace">No Warning/Error/Critical events were found.</text>');
            }

            const laneIndexOf = (channel) => {
                const idx = lanes.indexOf(channel);
                return idx >= 0 ? idx : lanes.length - 1;
            };

            events.forEach((ev, i) => {
                const y = eventsTop + i * rowH;
                const laneIdx = laneIndexOf(ev.channel);
                const cx = laneCenter(laneIdx);
                const style = EVENT_VIEWER_SEVERITY_STYLE[ev.severity] || EVENT_VIEWER_SEVERITY_STYLE.Warning;
                const nodeColor = style.node;
                const boxW = laneW - 34;
                const boxH = 46;
                const bx = cx - boxW / 2;
                const by = y - boxH / 2;

                parts.push('<g class="fa-row" data-idx="' + i + '">');
                // Timestamp gutter + connector to the lane.
                if (ev.timestamp) {
                    parts.push('<text x="12" y="' + (y + 4) + '" fill="#b8c0cc" font-size="11.5" font-weight="500" font-family="monospace">' + escapeHtml(truncateText(ev.timestamp, 26)) + '</text>');
                }
                parts.push('<line x1="' + (marginLeft - 20) + '" y1="' + y + '" x2="' + bx + '" y2="' + y + '" stroke="' + nodeColor + '" stroke-width="1.4" stroke-dasharray="3 4" opacity="0.6"/>');
                parts.push('<circle cx="' + (marginLeft - 20) + '" cy="' + y + '" r="4" fill="' + nodeColor + '"/>');

                // Event card.
                const sev = escapeHtml(ev.severity);
                const provider = escapeHtml(truncateText(ev.provider || 'Unknown', 26));
                const idLabel = 'ID ' + escapeHtml(String(ev.eventId != null ? ev.eventId : 0));
                const msg = escapeHtml(truncateText(String(ev.raw || '').replace(/\s+/g, ' '), 40));
                parts.push('<rect x="' + bx + '" y="' + by + '" width="' + boxW + '" height="' + boxH + '" rx="8" fill="rgba(2,6,23,0.85)" stroke="' + nodeColor + '" stroke-width="1.7"/>');
                parts.push('<rect x="' + bx + '" y="' + by + '" width="5" height="' + boxH + '" rx="2" fill="' + nodeColor + '"/>');
                parts.push('<text x="' + (bx + 14) + '" y="' + (by + 18) + '" fill="' + style.text + '" font-size="12" font-weight="700" font-family="monospace">' + (style.isErr ? '\u26a0 ' : '') + sev + ' \u00b7 ' + provider + ' \u00b7 ' + idLabel + '</text>');
                parts.push('<text x="' + (bx + 14) + '" y="' + (by + 36) + '" fill="#cbd5e1" font-size="11" font-family="monospace">' + msg + '</text>');

                // Full-row hit area for clicking.
                parts.push('<rect class="fa-hit" x="0" y="' + (y - rowH / 2 + 4) + '" width="' + width + '" height="' + (rowH - 8) + '" fill="transparent"/>');
                parts.push('</g>');
            });

            parts.push('</svg>');
            return parts.join('');
        }

        function buildEventViewerFlowDocument(model, title) {
            const safeTitle = escapeHtml(title || 'Visual Flow Analyzer \u00b7 Event Viewer Logs');
            const summaryBits = (Array.isArray(model.summaryBits) ? model.summaryBits : [])
                .filter(Boolean).map(escapeHtml).join('  &nbsp;|&nbsp;  ');
            const svg = renderEventViewerSwimlaneSvg(model);
            const eventsJson = JSON.stringify((model.events || []).map(function (ev) {
                return { label: ev.label || '', timestamp: ev.timestamp || '', raw: ev.raw || '', logIndex: (typeof ev.logIndex === 'number' ? ev.logIndex : -1), error: !!ev.error };
            })).replace(/<\//g, '<\\/');
            const logJson = JSON.stringify(Array.isArray(model.logLines) ? model.logLines : [])
                .replace(/<\//g, '<\\/');
            return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
                + '<meta name="viewport" content="width=device-width, initial-scale=1">'
                + '<title>' + safeTitle + '</title>'
                + '<style>'
                + 'body{margin:0;background:#0b1220;color:#e2e8f0;font-family:ui-monospace,Menlo,Consolas,monospace;}'
                + '.wrap{max-width:1200px;margin:0 auto;padding:24px;}'
                + 'h1{font-size:14px;letter-spacing:.15em;text-transform:uppercase;color:#7dd3fc;margin:0 0 12px;}'
                + '.summary{font-size:12px;color:#cbd5e1;margin-bottom:10px;line-height:1.7;}'
                + '.legend{font-size:12px;margin-bottom:16px;display:flex;gap:22px;flex-wrap:wrap;}'
                + '.legend .er{color:#fca5a5;}.legend .cr{color:#fda4af;}.legend .wa{color:#fcd34d;}'
                + '.diagram{background:#020617;border:1px solid rgba(56,189,248,.25);border-radius:12px;padding:16px;overflow:auto;}'
                + '.toolbar{display:flex;gap:10px;margin:0 0 14px;flex-wrap:wrap;}'
                + '.btn{cursor:pointer;font-family:inherit;font-size:12px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#e2e8f0;background:rgba(56,189,248,.14);border:1px solid rgba(56,189,248,.45);border-radius:8px;padding:8px 14px;}'
                + '.btn:hover{background:rgba(56,189,248,.26);}'
                + '.fa-row{cursor:pointer;}'
                + '.fa-row:hover .fa-hit{fill:rgba(56,189,248,.08);}'
                + '.fa-row.sel .fa-hit{fill:rgba(56,189,248,.14);}'
                + '.hint{font-size:11px;color:#64748b;margin:10px 0 0;letter-spacing:.04em;}'
                + '.detail{margin-top:14px;background:#020617;border:1px solid rgba(56,189,248,.25);border-radius:12px;padding:14px 16px;font-size:12px;}'
                + '.detail .dl{color:#7dd3fc;font-weight:700;margin-bottom:8px;}'
                + '.detail .ts{color:#b8c0cc;font-weight:500;margin-bottom:8px;}'
                + '.detail pre{margin:0;white-space:pre-wrap;word-break:break-word;color:#e2e8f0;line-height:1.6;}'
                + '.detail .muted{color:#64748b;}'
                + '.detail .dh{margin-bottom:8px;}'
                + '.detail .dh .dl{display:inline;margin:0;}'
                + '.logbox{position:relative;max-height:380px;overflow:auto;background:#0b1220;border:1px solid rgba(56,189,248,.18);border-radius:8px;padding:8px 10px;margin-top:10px;font-size:11px;line-height:1.6;}'
                + '.logline{white-space:pre-wrap;word-break:break-word;color:#8b97a8;padding:1px 6px;border-left:2px solid transparent;}'
                + '.logline.hl{background:rgba(251,191,36,.16);color:#fde68a;border-left:2px solid #fbbf24;}'
                + '.logline.hlerr{background:rgba(248,113,113,.16);color:#fecaca;border-left:2px solid #f87171;}'
                + '</style></head><body><div class="wrap">'
                + '<h1>' + safeTitle + '</h1>'
                + '<div class="summary">' + summaryBits + '</div>'
                + '<div class="legend">'
                + '<span class="er">&#9888; Error</span>'
                + '<span class="cr">&#9888; Critical</span>'
                + '<span class="wa">&#9888; Warning</span>'
                + '</div>'
                + '<div class="toolbar">'
                + '<button id="fa-dl-svg" class="btn" type="button">Download SVG</button>'
                + '<button id="fa-dl-png" class="btn" type="button">Download PNG</button>'
                + '</div>'
                + '<div class="diagram">' + svg + '</div>'
                + '<p class="hint">Tip: click any event node to highlight its full detail within the log below.</p>'
                + '<div id="fa-detail" class="detail"><div class="muted">Click any event above to view its raw detail.</div></div>'
                + '</div>'
                + '<script>window.__FA_EVENTS__=' + eventsJson + ';<\/script>'
                + '<script>window.__FA_LOG__=' + logJson + ';<\/script>'
                + '<script>' + flowDownloadScript() + '<\/script>'
                + '<script>' + flowInteractScript() + '<\/script>'
                + '</body></html>';
        }

        function openEventViewerFlowTab(model, title) {
            const html = buildEventViewerFlowDocument(model, title);
            const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
            const objectUrl = URL.createObjectURL(blob);
            const newTab = window.open(objectUrl, '_blank');
            if (!newTab) {
                alert('Please allow pop-ups for this site to open the Visual Flow Analyzer in a new tab.');
            }
            window.setTimeout(function () {
                URL.revokeObjectURL(objectUrl);
            }, 120000);
        }

        function renderEventViewerSummary(summary) {
            resetEventViewerSummary();
            if (!summary || !eventViewerSummaryWrap) {
                return;
            }

            const events = Array.isArray(summary.events) ? summary.events : [];
            const channelOrder = Array.isArray(summary.channel_order) && summary.channel_order.length
                ? summary.channel_order
                : ['Application', 'System', 'ZTA'];
            const counts = summary.counts || {};
            const totals = { Error: 0, Critical: 0, Warning: 0 };
            channelOrder.forEach((ch) => {
                const row = counts[ch] || {};
                ['Error', 'Critical', 'Warning'].forEach((sev) => {
                    totals[sev] += Number(row[sev]) || 0;
                });
            });

            if (eventViewerTimeRange) {
                eventViewerTimeRange.textContent = `Time Range: ${summary.time_range_display || 'unavailable'}`;
            }
            if (eventViewerNote && summary.note) {
                eventViewerNote.textContent = summary.note;
                eventViewerNote.classList.remove('hidden');
            }

            // Stat cards.
            if (eventViewerStatCards) {
                const cards = [
                    { label: 'Total Events', value: String(events.length), tone: 'text-sky-200' },
                    { label: 'Error', value: String(totals.Error), tone: totals.Error ? 'text-red-600' : 'text-slate-400' },
                    { label: 'Critical', value: String(totals.Critical), tone: totals.Critical ? 'text-rose-600' : 'text-slate-400' },
                    { label: 'Warning', value: String(totals.Warning), tone: totals.Warning ? 'text-amber-600' : 'text-slate-400' },
                ];
                cards.forEach((card) => {
                    const box = document.createElement('div');
                    box.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-3';
                    const val = document.createElement('div');
                    val.className = `text-2xl font-bold ${card.tone}`;
                    val.textContent = card.value;
                    const lbl = document.createElement('div');
                    lbl.className = 'text-xs uppercase tracking-wide text-sky-200/60';
                    lbl.textContent = card.label;
                    box.appendChild(val);
                    box.appendChild(lbl);
                    eventViewerStatCards.appendChild(box);
                });
            }

            // Top recurring events (per severity), for events that occur multiple times.
            if (eventViewerTopEvents && events.length) {
                const normalizeMsgKey = (m) => String(m || '').replace(/\s+/g, ' ').trim().slice(0, 140).toLowerCase();
                const severitiesInOrder = ['Error', 'Critical', 'Warning'];
                const recurringBySeverity = {};
                severitiesInOrder.forEach((sev) => {
                    const map = new Map();
                    events.filter((e) => String(e.severity || 'Warning') === sev).forEach((e) => {
                        const provider = e.provider || 'Unknown';
                        const eventId = e.event_id != null ? e.event_id : 0;
                        const key = `${provider}||${eventId}||${normalizeMsgKey(e.message)}`;
                        let g = map.get(key);
                        if (!g) {
                            g = { count: 0, provider, eventId, message: e.message || '', channel: e.channel || 'System', sources: new Set() };
                            map.set(key, g);
                        }
                        g.count += 1;
                        if (e.source) {
                            g.sources.add(e.source);
                        }
                    });
                    recurringBySeverity[sev] = Array.from(map.values())
                        .filter((g) => g.count >= 2)
                        .sort((a, b) => b.count - a.count)
                        .slice(0, 5);
                });

                const anyRecurring = severitiesInOrder.some((sev) => recurringBySeverity[sev].length);
                if (anyRecurring) {
                    const topCard = document.createElement('div');
                    topCard.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-4';
                    const topHeading = document.createElement('div');
                    topHeading.className = 'mb-3 text-sm font-bold uppercase tracking-wide text-sky-300';
                    topHeading.textContent = 'Top Indicators';
                    topCard.appendChild(topHeading);

                    severitiesInOrder.forEach((sev) => {
                        const groups = recurringBySeverity[sev];
                        if (!groups.length) {
                            return;
                        }
                        const style = EVENT_VIEWER_SEVERITY_STYLE[sev] || EVENT_VIEWER_SEVERITY_STYLE.Warning;
                        const section = document.createElement('div');
                        section.className = 'mb-4';
                        const secTitle = document.createElement('div');
                        secTitle.className = 'mb-2 flex items-center gap-2';
                        const secBadge = document.createElement('span');
                        secBadge.className = `inline-flex items-center rounded-full border px-2.5 py-0.5 text-sm font-bold ${style.badge}`;
                        secBadge.textContent = (style.isErr ? '\u26a0 ' : '') + sev;
                        secTitle.appendChild(secBadge);
                        section.appendChild(secTitle);

                        groups.forEach((g) => {
                            const row = document.createElement('div');
                            row.className = 'py-1.5 pl-1 text-sm leading-relaxed text-slate-700';
                            row.innerHTML = `<span class="font-semibold text-slate-800">${escapeHtml(g.provider)} · ${escapeHtml(String(g.eventId))}</span> <span class="text-sky-700">[${escapeHtml(g.channel)}]</span> `
                                + `${escapeHtml(String(g.message || '').replace(/\s+/g, ' '))}`;
                            section.appendChild(row);
                        });

                        topCard.appendChild(section);
                    });

                    eventViewerTopEvents.appendChild(topCard);
                }
            }

            // Events table with a channel filter and a per-channel Visual Flow.
            let activeChannel = 'All';
            let applyChannelFilter = null;
            if (eventViewerTable) {
                const card = document.createElement('div');
                card.className = 'rounded-lg border border-sky-500/20 bg-black/20 p-3';

                const heading = document.createElement('div');
                heading.className = 'mb-2 flex items-center justify-between';
                const headingTitle = document.createElement('div');
                headingTitle.className = 'text-xs font-bold uppercase tracking-wide text-sky-300';
                headingTitle.textContent = `Event Viewer Events (${events.length})`;
                const headingMeta = document.createElement('div');
                headingMeta.className = 'text-xs font-semibold';
                headingMeta.innerHTML = events.length
                    ? `<span class="text-red-600">${totals.Error} err</span> \u00b7 <span class="text-rose-600">${totals.Critical} crit</span> \u00b7 <span class="text-amber-600">${totals.Warning} warn</span>`
                    : '<span class="text-slate-400">none</span>';
                heading.appendChild(headingTitle);
                heading.appendChild(headingMeta);
                card.appendChild(heading);

                if (events.length) {
                    // Helpers to detect events inside the ZeroTrustAccess.txt-derived failure window.
                    // Event timestamps and the timeframe share a "YYYY-MM-DD HH:MM:SS" prefix, so
                    // fixed-width lexical comparison is sufficient (no timezone math needed).
                    const extractTs = (s) => {
                        const m = String(s || '').match(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/);
                        return m ? m[0] : '';
                    };
                    const winStart = extractTs(summary.timeframe_start);
                    const winEnd = extractTs(summary.timeframe_end);
                    const inWindow = (ts) => {
                        const t = extractTs(ts);
                        return !!(winStart && winEnd && t && t >= winStart && t <= winEnd);
                    };

                    // Channel filter tabs (All + each channel with counts).
                    const channelCounts = {};
                    channelOrder.forEach((ch) => {
                        channelCounts[ch] = events.filter((e) => String(e.channel || 'System') === ch).length;
                    });
                    const filterBar = document.createElement('div');
                    filterBar.className = 'mb-2 flex flex-wrap items-center gap-2';
                    const filterLabel = document.createElement('span');
                    filterLabel.className = 'text-xs font-semibold uppercase tracking-wide text-sky-200/60';
                    filterLabel.textContent = 'Service:';
                    filterBar.appendChild(filterLabel);

                    const tabDefs = [{ key: 'All', label: `All (${events.length})` }]
                        .concat(channelOrder.map((ch) => ({ key: ch, label: `${ch} (${channelCounts[ch] || 0})` })));
                    const tabButtons = {};

                    applyChannelFilter = () => {
                        Object.keys(tabButtons).forEach((key) => {
                            const active = key === activeChannel;
                            tabButtons[key].className = active
                                ? 'rounded-full border border-sky-500 bg-sky-500/20 px-3 py-1 text-xs font-bold text-sky-700'
                                : 'rounded-full border border-sky-500/30 px-3 py-1 text-xs font-semibold text-slate-500 hover:bg-sky-500/10';
                        });
                        const groupEls = card.querySelectorAll('.ev-group[data-channel]');
                        let visible = 0;
                        groupEls.forEach((el) => {
                            const show = activeChannel === 'All' || el.getAttribute('data-channel') === activeChannel;
                            el.style.display = show ? '' : 'none';
                            if (show) {
                                visible += Number(el.getAttribute('data-count')) || 0;
                            }
                        });
                        headingTitle.textContent = `Event Viewer Events (${visible})`;
                        card.querySelectorAll('.ev-src-col').forEach((el) => {
                            el.style.display = activeChannel === 'All' ? '' : 'none';
                        });
                    };

                    tabDefs.forEach((def) => {
                        const btn = document.createElement('button');
                        btn.type = 'button';
                        btn.textContent = def.label;
                        btn.addEventListener('click', () => {
                            activeChannel = def.key;
                            applyChannelFilter();
                        });
                        tabButtons[def.key] = btn;
                        filterBar.appendChild(btn);
                    });
                    card.appendChild(filterBar);

                    // Collapse identical events (channel + severity + provider + id + message)
                    // into one expandable row showing occurrence count and first/last seen.
                    const normKey = (m) => String(m || '').replace(/\s+/g, ' ').trim().slice(0, 200).toLowerCase();
                    const groupMap = new Map();
                    events.forEach((ev) => {
                        const channel = String(ev.channel || 'System');
                        const severity = String(ev.severity || 'Warning');
                        const provider = ev.provider || 'Unknown';
                        const eventId = ev.event_id != null ? ev.event_id : 0;
                        const key = `${channel}||${severity}||${provider}||${eventId}||${normKey(ev.message)}`;
                        let g = groupMap.get(key);
                        if (!g) {
                            g = { channel, severity, provider, eventId, message: ev.message || '', count: 0, firstTs: '', lastTs: '', sources: new Set(), occurrences: [], anyInWindow: false };
                            groupMap.set(key, g);
                        }
                        g.count += 1;
                        const ts = ev.timestamp || 'Unknown';
                        const tsCore = extractTs(ts);
                        if (tsCore) {
                            if (!g.firstTs || tsCore < extractTs(g.firstTs)) { g.firstTs = ts; }
                            if (!g.lastTs || tsCore > extractTs(g.lastTs)) { g.lastTs = ts; }
                        } else if (!g.firstTs) {
                            g.firstTs = ts;
                            g.lastTs = ts;
                        }
                        if (ev.source) { g.sources.add(ev.source); }
                        if (inWindow(ts)) { g.anyInWindow = true; }
                        g.occurrences.push({ timestamp: ts, source: ev.source || 'Unknown' });
                    });

                    const sevRank = { Error: 0, Critical: 1, Warning: 2, Information: 3, Verbose: 4, Unknown: 5 };
                    const groupList = Array.from(groupMap.values()).sort((a, b) => {
                        const sr = (sevRank[a.severity] != null ? sevRank[a.severity] : 3) - (sevRank[b.severity] != null ? sevRank[b.severity] : 3);
                        if (sr !== 0) { return sr; }
                        return b.count - a.count;
                    });

                    const scroll = document.createElement('div');
                    scroll.className = 'max-h-96 overflow-auto rounded-lg border border-sky-500/15 divide-y divide-sky-500/10';

                    groupList.forEach((g) => {
                        const style = EVENT_VIEWER_SEVERITY_STYLE[g.severity] || EVENT_VIEWER_SEVERITY_STYLE.Warning;
                        const groupEl = document.createElement('div');
                        groupEl.className = 'ev-group' + (g.anyInWindow ? ' border-l-2 border-l-amber-400' : '');
                        groupEl.setAttribute('data-channel', g.channel);
                        groupEl.setAttribute('data-count', String(g.count));

                        const head = document.createElement('button');
                        head.type = 'button';
                        head.className = 'flex w-full items-start gap-2 px-2 py-2 text-left hover:bg-sky-500/5';

                        const caret = document.createElement('span');
                        caret.className = 'mt-0.5 shrink-0 text-sky-500 transition-transform';
                        caret.textContent = '\u25b8';

                        const badge = document.createElement('span');
                        badge.className = `mt-0.5 shrink-0 inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-bold ${style.badge}`;
                        badge.textContent = (style.isErr ? '\u26a0 ' : '') + g.severity;

                        const countPill = document.createElement('span');
                        countPill.className = 'mt-0.5 shrink-0 inline-flex items-center rounded bg-sky-500/15 px-1.5 py-0.5 text-[11px] font-bold text-sky-700';
                        countPill.textContent = `\u00d7${g.count}`;

                        const body = document.createElement('div');
                        body.className = 'min-w-0 flex-1';
                        const line1 = document.createElement('div');
                        line1.className = 'flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs';
                        const sameEnds = extractTs(g.firstTs) === extractTs(g.lastTs);
                        const timeText = (g.count > 1 && !sameEnds) ? `${g.firstTs} \u2192 ${g.lastTs}` : (g.firstTs || 'Unknown');
                        const srcArr = Array.from(g.sources);
                        line1.innerHTML = `<span class="font-semibold text-slate-800">${escapeHtml(g.provider)} \u00b7 ${escapeHtml(String(g.eventId))}</span>`
                            + `<span class="text-sky-700">[${escapeHtml(g.channel)}]</span>`
                            + `<span class="font-mono text-slate-500">${escapeHtml(timeText)}</span>`
                            + (g.anyInWindow ? '<span class="font-semibold text-amber-700">\u25cf in failure window</span>' : '')
                            + (srcArr.length ? `<span class="ev-src-col font-mono text-slate-400">${escapeHtml(srcArr.join(', '))}</span>` : '');
                        const line2 = document.createElement('div');
                        line2.className = 'mt-0.5 truncate text-xs text-slate-700';
                        line2.textContent = String(g.message || '').replace(/\s+/g, ' ') || '(no message)';
                        body.appendChild(line1);
                        body.appendChild(line2);

                        head.appendChild(caret);
                        head.appendChild(badge);
                        head.appendChild(countPill);
                        head.appendChild(body);

                        const detail = document.createElement('div');
                        detail.className = 'hidden bg-black/20 px-3 pb-3';
                        const full = document.createElement('div');
                        full.className = 'py-2 text-xs leading-relaxed text-slate-700 whitespace-pre-wrap break-words';
                        full.textContent = String(g.message || '') || '(no message)';
                        detail.appendChild(full);
                        if (g.occurrences.length > 1) {
                            const occTitle = document.createElement('div');
                            occTitle.className = 'mb-1 text-[11px] font-semibold uppercase tracking-wide text-sky-200/60';
                            occTitle.textContent = `${g.occurrences.length} occurrences`;
                            detail.appendChild(occTitle);
                            const occWrap = document.createElement('div');
                            occWrap.className = 'flex max-h-40 flex-col gap-0.5 overflow-auto';
                            g.occurrences.slice().sort((a, b) => extractTs(a.timestamp).localeCompare(extractTs(b.timestamp))).forEach((o) => {
                                const orow = document.createElement('div');
                                orow.className = 'flex items-center gap-2 text-[11px]' + (inWindow(o.timestamp) ? ' text-amber-800' : ' text-slate-500');
                                orow.innerHTML = `<span class="font-mono">${escapeHtml(o.timestamp)}</span>`
                                    + `<span class="ev-src-col font-mono text-slate-400">${escapeHtml(o.source)}</span>`;
                                occWrap.appendChild(orow);
                            });
                            detail.appendChild(occWrap);
                        }

                        let expanded = false;
                        head.addEventListener('click', () => {
                            expanded = !expanded;
                            detail.classList.toggle('hidden', !expanded);
                            caret.style.transform = expanded ? 'rotate(90deg)' : '';
                        });

                        groupEl.appendChild(head);
                        groupEl.appendChild(detail);
                        scroll.appendChild(groupEl);
                    });

                    card.appendChild(scroll);
                } else {
                    const empty = document.createElement('div');
                    empty.className = 'text-sm text-slate-400';
                    empty.textContent = 'No Warning/Error/Critical events were found for the derived timeframe.';
                    card.appendChild(empty);
                }

                eventViewerTable.appendChild(card);
            }

            // Download link (per-service viewing is handled by the Service filter above).
            if (eventViewerDownloads) {
                if (typeof summary.download_text === 'string' && summary.download_text) {
                    const blob = new Blob([summary.download_text], { type: 'text/csv;charset=utf-8' });
                    const objectUrl = URL.createObjectURL(blob);
                    eventViewerSummaryDownloadUrls.push(objectUrl);
                    const link = document.createElement('a');
                    link.href = objectUrl;
                    link.download = String(summary.download_filename || 'event_viewer_filtered_events.csv');
                    link.className = 'inline-flex items-center rounded border border-sky-500/50 px-3 py-1.5 text-sm font-bold tracking-wide text-sky-200 hover:bg-sky-500/10';
                    link.textContent = 'Download Event Viewer CSV';
                    eventViewerDownloads.appendChild(link);
                }
            }

            if (applyChannelFilter) {
                applyChannelFilter();
            }

            eventViewerSummaryWrap.classList.remove('hidden');
        }

        function setCopyResultButtonState(isEnabled) {
            if (!copyResultButton) {
                return;
            }

            copyResultButton.disabled = !isEnabled;
            copyResultButton.classList.toggle('opacity-40', !isEnabled);
            copyResultButton.classList.toggle('cursor-not-allowed', !isEnabled);
        }

        function setAnalysisIndicatorState(state, message) {
            if (!analysisIndicator || !analysisIndicatorText || !analysisIndicatorPulse) {
                return;
            }

            if (analysisIndicatorResetTimer) {
                window.clearTimeout(analysisIndicatorResetTimer);
                analysisIndicatorResetTimer = null;
            }

            if (state === 'idle') {
                analysisIndicator.classList.add('hidden');
                return;
            }

            analysisIndicator.classList.remove('hidden');
            analysisIndicatorText.textContent = message || 'Processing analysis request...';

            analysisIndicator.classList.remove('border-sky-500/30', 'border-emerald-500/40', 'border-rose-500/40');
            analysisIndicatorPulse.classList.remove('bg-sky-300', 'bg-emerald-300', 'bg-rose-300', 'animate-pulse');

            if (state === 'processing') {
                analysisIndicator.classList.add('border-sky-500/30');
                analysisIndicatorPulse.classList.add('bg-sky-300', 'animate-pulse');
                return;
            }

            if (state === 'success') {
                analysisIndicator.classList.add('border-emerald-500/40');
                analysisIndicatorPulse.classList.add('bg-emerald-300');
            } else {
                analysisIndicator.classList.add('border-rose-500/40');
                analysisIndicatorPulse.classList.add('bg-rose-300');
            }

            analysisIndicatorResetTimer = window.setTimeout(() => {
                setAnalysisIndicatorState('idle');
            }, 6000);
        }

        async function copyTextToClipboard(text) {
            const normalizedText = String(text || '');
            if (!normalizedText) {
                return false;
            }

            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(normalizedText);
                return true;
            }

            const textArea = document.createElement('textarea');
            textArea.value = normalizedText;
            textArea.setAttribute('readonly', '');
            textArea.style.position = 'fixed';
            textArea.style.opacity = '0';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();

            let copied = false;
            try {
                copied = document.execCommand('copy');
            } finally {
                document.body.removeChild(textArea);
            }

            return copied;
        }

        async function copyRichResultToClipboard(plainText, resultHtml) {
            const normalizedPlainText = String(plainText || '');
            if (!normalizedPlainText) {
                return false;
            }

            // Copy plain text only to keep pasted output readable in editors like Notepad.
            return copyTextToClipboard(normalizedPlainText);
        }

        async function handleCopyResultOutput() {
            if (!resultContent || !copyResultButton) {
                return;
            }

            const outputText = String(resultContent.textContent || '').trim();
            const outputHtml = String(resultContent.innerHTML || '').trim();
            if (!outputText) {
                setCopyResultButtonState(false);
                return;
            }

            const originalLabel = 'Copy Output';
            if (copyResultButtonResetTimer) {
                clearTimeout(copyResultButtonResetTimer);
                copyResultButtonResetTimer = null;
            }

            try {
                const copied = await copyRichResultToClipboard(outputText, outputHtml);
                copyResultButton.textContent = copied ? 'Copied' : 'Copy Failed';
            } catch (_error) {
                copyResultButton.textContent = 'Copy Failed';
            }

            copyResultButtonResetTimer = window.setTimeout(() => {
                copyResultButton.textContent = originalLabel;
                copyResultButtonResetTimer = null;
            }, 1500);
        }

        function updateResultPaneForOptionInteraction(forceHide = false) {
            if (!resultArea || !resultContent) {
                return;
            }

            const hasExistingOutput = String(resultContent.textContent || '').trim().length > 0;
            setCopyResultButtonState(hasExistingOutput);
            setResultSearchState(hasExistingOutput);
            if (forceHide || !hasExistingOutput) {
                resultArea.classList.add('hidden');
                return;
            }

            resultArea.classList.remove('hidden');
        }

        function setResultOutputPanelVisibility(showPanel) {
            const shouldShow = Boolean(showPanel);
            if (resultHeaderRow) {
                resultHeaderRow.classList.toggle('hidden', !shouldShow);
            }
            if (resultSearchRow) {
                resultSearchRow.classList.toggle('hidden', !shouldShow);
            }
            if (resultOutputPanel) {
                resultOutputPanel.classList.toggle('hidden', !shouldShow);
            }
        }

        function updateScrollToTopVisibility() {
            if (!scrollToTopBtn) {
                return;
            }
            const shouldShow = window.scrollY > 260;
            scrollToTopBtn.classList.toggle('hidden', !shouldShow);
        }

        function resetSpaFields() {
            spaCheckRadios.forEach((radio) => {
                radio.checked = false;
            });
            spaEnrollmentTypeRadios.forEach((radio) => {
                radio.checked = false;
            });
            srvCheckOptionRadios.forEach((radio) => {
                radio.checked = false;
            });
            spaTargetInput.value = '';
            srvConfigFilterInput.value = '';
            srvFlowFilterInput.value = '';
            if (srvFlowStartTime) {
                srvFlowStartTime.value = '';
            }
            if (srvFlowEndTime) {
                srvFlowEndTime.value = '';
            }
            spaFlowSourcePort.value = '';
            spaTargetInputWrap.classList.add('hidden');
            spaFlowSourcePortWrap.classList.add('hidden');
            spaFlowFilterWrap.classList.add('hidden');
            spaFlowCandidatesWrap.classList.add('hidden');
            spaFlowCandidatesList.innerHTML = '';
            spaFlowSelectedBadge.classList.add('hidden');
            spaFlowSelectedBadge.textContent = '';
            spaFlowSummary.classList.add('hidden');
            spaFlowSummary.textContent = '';
            selectedFlowCandidateSrcPort = '';
            spaFlowDestinationPort.value = '';
            spaFlowStartDate.value = '';
            spaFlowStartHour.value = '';
            spaFlowStartMinute.value = '';
            spaFlowEndDate.value = '';
            spaFlowEndHour.value = '';
            spaFlowEndMinute.value = '';
            spaEnrollmentTypeWrap.classList.add('hidden');
            if (evtxScanLimitWrap) {
                evtxScanLimitWrap.classList.add('hidden');
            }
            if (evtxScanLimit) {
                evtxScanLimit.value = evtxScanLimit.defaultValue || '60000';
            }
            if (srvQuickActionWrap) {
                srvQuickActionWrap.classList.add('hidden');
            }
            if (srvConfigFilterWrap) {
                srvConfigFilterWrap.classList.add('hidden');
            }
            if (srvFlowFilterWrap) {
                srvFlowFilterWrap.classList.add('hidden');
            }
            if (srvFlowCandidatesWrap) {
                srvFlowCandidatesWrap.classList.add('hidden');
            }
            if (srvFlowCandidatesList) {
                srvFlowCandidatesList.innerHTML = '';
            }
            if (srvFlowSelectedBadge) {
                srvFlowSelectedBadge.classList.add('hidden');
                srvFlowSelectedBadge.textContent = '';
            }
            if (srvFlowSummary) {
                srvFlowSummary.classList.add('hidden');
                srvFlowSummary.textContent = '';
            }
            selectedSrvFlowIdentifier = '';
        }

        function clearSpaFlowSelectionState(showHint = false) {
            pendingTransactionAnalysis = null;
            selectedFlowCandidateSrcPort = '';
            spaFlowSourcePort.value = '';
            spaFlowCandidatesWrap.classList.add('hidden');
            spaFlowCandidatesList.innerHTML = '';
            spaFlowSelectedBadge.classList.add('hidden');
            spaFlowSelectedBadge.textContent = '';
            spaFlowSummary.classList.add('hidden');
            spaFlowSummary.textContent = '';
            setTransactionDownloadLinkState(false);

            if (showHint && spaTargetInputHint) {
                spaTargetInputHint.classList.remove('hidden');
                spaTargetInputHint.textContent = 'Target changed. Click Initiate Analysis to refresh SPA Flow matches.';
            }
        }

        function clearOutputOnFlowFilterInteraction() {
            clearSpaFlowSelectionState(false);
            pendingSrvTransactionAnalysis = null;
            selectedSrvFlowIdentifier = '';

            if (srvFlowCandidatesWrap) {
                srvFlowCandidatesWrap.classList.add('hidden');
            }
            if (srvFlowCandidatesList) {
                srvFlowCandidatesList.innerHTML = '';
            }
            if (srvFlowSelectedBadge) {
                srvFlowSelectedBadge.classList.add('hidden');
                srvFlowSelectedBadge.textContent = '';
            }
            if (srvFlowSummary) {
                srvFlowSummary.classList.add('hidden');
                srvFlowSummary.textContent = '';
            }

            latestResultRawText = '';
            if (resultContent) {
                resultContent.textContent = '';
            }
            if (resultSearchInput) {
                resultSearchInput.value = '';
            }
            updateResultSearchCount(0, false);
            setResultSearchState(false);
            setCopyResultButtonState(false);
            setResultDownloadLinkState(false);
            setEnrollmentResultDownloadLinkState(false);
            setEnrollmentFlowVisualButtonState(false);
            resetEnrollmentAttempts();
            setCachedConfigDownloadLinkState(false);
            setTransactionDownloadLinkState(false);
            resetServerConnectivitySummary();
            resetConfigSyncSummary();
            resetEventViewerSummary();
            resetTndSummary();
            resetDuoPostureFlowSummary();
            resetAiInsightCard();

            if (resultArea) {
                resultArea.classList.add('hidden');
            }
        }

        function toggleSrvCheckInputs() {
            const selectedSpaCheck = document.querySelector('input[name="spa_check_option"]:checked');
            const shouldShowSrv = selectedSpaCheck && selectedSpaCheck.value === 'SRV Check';

            if (srvQuickActionWrap) {
                srvQuickActionWrap.classList.toggle('hidden', !shouldShowSrv);
            }
            if (srvConfigFilterWrap) {
                srvConfigFilterWrap.classList.toggle('hidden', !shouldShowSrv);
            }
            if (srvFlowFilterWrap) {
                srvFlowFilterWrap.classList.toggle('hidden', !shouldShowSrv);
            }
            if (!shouldShowSrv || !String(srvFlowFilterInput.value || '').trim()) {
                selectedSrvFlowIdentifier = '';
                if (srvFlowCandidatesWrap) {
                    srvFlowCandidatesWrap.classList.add('hidden');
                }
                if (srvFlowCandidatesList) {
                    srvFlowCandidatesList.innerHTML = '';
                }
                if (srvFlowSelectedBadge) {
                    srvFlowSelectedBadge.classList.add('hidden');
                    srvFlowSelectedBadge.textContent = '';
                }
                if (srvFlowSummary) {
                    srvFlowSummary.classList.add('hidden');
                    srvFlowSummary.textContent = '';
                }
            }
        }

        function buildSrvAttemptFallbackLogText(candidate) {
            const timeframeText = (
                candidate.timeframe_start
                && candidate.timeframe_end
                && candidate.timeframe_start !== candidate.timeframe_end
            )
                ? `${candidate.timeframe_start} -> ${candidate.timeframe_end}`
                : (candidate.timeframe_start || candidate.timeframe_end || 'Unknown');
            return [
                'SRV Flow Attempt Export',
                `Identifier: ${candidate.identifier || 'Unknown'}`,
                `Events: ${candidate.event_count || 0}`,
                `Timeframe: ${timeframeText}`,
                `SRV: ${candidate.srv || 'Unknown'}`,
            ].join(String.fromCharCode(10));
        }

        function buildSrvTraceContent(traceRows) {
            return (traceRows || [])
                .map((row) => row && row.line ? String(row.line) : '')
                .filter((line) => Boolean(line))
                .join(String.fromCharCode(10));
        }

        function renderSrvFlowCandidates(data, detailsText) {
            const candidates = Array.isArray(data && data.srv_flow_candidates) ? data.srv_flow_candidates : [];
            const traceRows = Array.isArray(data && data.srv_selected_identifier_trace) ? data.srv_selected_identifier_trace : [];
            const selectedIdentifier = String(data && data.srv_selected_identifier ? data.srv_selected_identifier : '').trim();

            if (!srvFlowCandidatesList) {
                return;
            }
            srvFlowCandidatesList.innerHTML = '';

            if (!candidates.length) {
                if (srvFlowCandidatesWrap) {
                    srvFlowCandidatesWrap.classList.add('hidden');
                }
                if (srvFlowSummary) {
                    srvFlowSummary.classList.add('hidden');
                    srvFlowSummary.textContent = '';
                }
                if (srvFlowSelectedBadge) {
                    srvFlowSelectedBadge.classList.add('hidden');
                    srvFlowSelectedBadge.textContent = '';
                }
                return;
            }

            if (srvFlowSummary) {
                const totalEvents = candidates.reduce((acc, item) => acc + Number(item.event_count || 0), 0);
                srvFlowSummary.className = 'mb-3 rounded-lg border border-sky-500/25 bg-sky-500/5 px-3 py-2 text-xs text-sky-100/90';
                srvFlowSummary.textContent = `Total Attempts: ${candidates.length} | Total Events: ${totalEvents}`;
                srvFlowSummary.classList.remove('hidden');
            }

            selectedSrvFlowIdentifier = selectedIdentifier;
            if (srvFlowSelectedBadge) {
                if (selectedIdentifier) {
                    srvFlowSelectedBadge.textContent = `Selected Identifier: ${selectedIdentifier}`;
                    srvFlowSelectedBadge.classList.remove('hidden');
                } else {
                    srvFlowSelectedBadge.classList.add('hidden');
                    srvFlowSelectedBadge.textContent = '';
                }
            }

            const traceByIdentifier = {};
            if (selectedIdentifier && traceRows.length) {
                traceByIdentifier[selectedIdentifier] = traceRows;
            }

            const tableWrap = document.createElement('div');
            tableWrap.className = 'overflow-x-auto';
            const table = document.createElement('table');
            table.className = 'w-full text-sm md:text-base border border-sky-500/25 rounded-lg overflow-hidden';
            table.innerHTML = `
                <thead class="bg-sky-900/40 text-sky-200 uppercase tracking-wider">
                    <tr>
                        <th class="text-left p-2 border-b border-sky-500/20">Identifier</th>
                        <th class="text-left p-2 border-b border-sky-500/20">Events</th>
                        <th class="text-left p-2 border-b border-sky-500/20">Timeframe</th>
                        <th class="text-left p-2 border-b border-sky-500/20">SRV</th>
                        <th class="text-left p-2 border-b border-sky-500/20">Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            `;

            const tbody = table.querySelector('tbody');

            async function fetchTraceRowsForIdentifier(identifier) {
                const selectedFile = dartFile.files && dartFile.files[0] ? dartFile.files[0] : null;
                const selectedModule = document.querySelector('input[name="module"]:checked');
                const selectedZtaMode = document.querySelector('input[name="zta_access_mode"]:checked');
                const selectedSpaCheck = document.querySelector('input[name="spa_check_option"]:checked');

                if (!selectedFile || !selectedModule || !selectedZtaMode || !selectedSpaCheck) {
                    return [];
                }

                const formData = new FormData();
                formData.append('file', selectedFile);
                formData.append('module', selectedModule.value);
                appendClientTimezoneOffset(formData);
                formData.append('zta_access_mode', selectedZtaMode.value);
                formData.append('spa_check_option', selectedSpaCheck.value);
                appendEvtxScanDepth(formData, selectedSpaCheck.value);
                formData.append('srv_flow_filter_value', srvFlowFilterInput.value.trim());
                formData.append('srv_flow_time_start', srvFlowStartTime ? srvFlowStartTime.value.trim() : '');
                formData.append('srv_flow_time_end', srvFlowEndTime ? srvFlowEndTime.value.trim() : '');
                formData.append('srv_selected_identifier', identifier);
                formData.append('show_full_cached_config', showFullCachedConfig.checked ? '1' : '0');
                formData.append('cached_config_search_term', cachedConfigSearch.value.trim());

                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        body: formData,
                    });
                    const payload = await response.json();
                    if (!response.ok) {
                        return [];
                    }
                    return Array.isArray(payload.srv_selected_identifier_trace)
                        ? payload.srv_selected_identifier_trace
                        : [];
                } catch (error) {
                    return [];
                }
            }

            candidates.forEach((candidate) => {
                const row = document.createElement('tr');
                row.className = 'border-b border-sky-500/10 hover:bg-white/5';

                const timeframeStart = candidate.timeframe_start || '';
                const timeframeEnd = candidate.timeframe_end || '';
                let timeframeMarkup = 'Unknown';
                if (timeframeStart && timeframeEnd && timeframeStart !== timeframeEnd) {
                    timeframeMarkup = `<div class="whitespace-nowrap">${timeframeStart}</div><div class="whitespace-nowrap">${timeframeEnd}</div>`;
                } else {
                    timeframeMarkup = `<div class="whitespace-nowrap">${timeframeStart || timeframeEnd || 'Unknown'}</div>`;
                }

                row.innerHTML = `
                    <td class="p-2 text-sky-100 font-bold font-mono whitespace-nowrap align-top">${candidate.identifier || 'Unknown'}</td>
                    <td class="p-2 text-sky-200/90 whitespace-nowrap align-top">${candidate.event_count || 0}</td>
                    <td class="p-2 text-sky-200/90 align-top">${timeframeMarkup}</td>
                    <td class="p-2 text-sky-200/80 break-all align-top">${candidate.srv || srvFlowFilterInput.value.trim() || 'Unknown'}</td>
                    <td class="p-2 text-sky-100"></td>
                `;

                const actionsCell = row.lastElementChild;
                const actionsWrap = document.createElement('div');
                actionsWrap.className = 'flex flex-col gap-2';

                const downloadButton = document.createElement('button');
                downloadButton.type = 'button';
                downloadButton.className = 'flow-download-btn rounded border border-emerald-400/40 px-2 py-1 text-sm md:text-base font-bold tracking-wide text-emerald-100 hover:bg-emerald-500/10';
                downloadButton.textContent = 'Download Logs';
                downloadButton.addEventListener('click', async () => {
                    const identifier = String(candidate.identifier || '').trim();
                    const filename = `srv_flow_identifier_${flowUtils.sanitizeFilenamePart(identifier || 'unknown')}.log`;
                    const originalText = downloadButton.textContent;
                    downloadButton.disabled = true;
                    downloadButton.textContent = 'Preparing...';

                    let rows = traceByIdentifier[identifier] || [];
                    if (!rows.length && identifier) {
                        rows = await fetchTraceRowsForIdentifier(identifier);
                        if (rows.length) {
                            traceByIdentifier[identifier] = rows;
                        }
                    }

                    const content = rows.length
                        ? buildSrvTraceContent(rows)
                        : buildSrvAttemptFallbackLogText(candidate);
                    flowUtils.triggerTextDownload(
                        filename,
                        emphasizeCriticalLinesForDownload(content || detailsText || '')
                    );

                    downloadButton.disabled = false;
                    downloadButton.textContent = originalText;
                });

                const initiateButton = document.createElement('button');
                initiateButton.type = 'button';
                initiateButton.className = 'flow-init-analysis-btn rounded px-3 py-2 text-sm md:text-base font-bold tracking-wide';
                initiateButton.textContent = 'Initiate Analysis';
                initiateButton.addEventListener('click', () => {
                    selectedSrvFlowIdentifier = String(candidate.identifier || '').trim();
                    pendingSrvTransactionAnalysis = {
                        identifier: selectedSrvFlowIdentifier,
                        srv: String(candidate.srv || srvFlowFilterInput.value.trim() || '').trim(),
                    };
                    uploadForm.requestSubmit();
                });

                const visualFlowButton = document.createElement('button');
                visualFlowButton.type = 'button';
                visualFlowButton.className = 'flow-visual-btn rounded border border-sky-400/40 px-2 py-1 text-sm md:text-base font-bold tracking-wide text-sky-100 hover:bg-sky-500/10';
                visualFlowButton.textContent = 'Visual Flow Analyzer';
                visualFlowButton.addEventListener('click', async () => {
                    if (!flowUtils || typeof flowUtils.buildSrvFlowModel !== 'function') {
                        return;
                    }
                    const identifier = String(candidate.identifier || '').trim();
                    const originalLabel = visualFlowButton.textContent;
                    visualFlowButton.disabled = true;
                    visualFlowButton.textContent = 'Building...';
                    try {
                        let rows = traceByIdentifier[identifier] || [];
                        if (!rows.length && identifier) {
                            rows = await fetchTraceRowsForIdentifier(identifier);
                            if (rows.length) {
                                traceByIdentifier[identifier] = rows;
                            }
                        }
                        const traceLineStrings = (rows || [])
                            .map((row) => {
                                if (!row) {
                                    return '';
                                }
                                const lineText = String(row.line || '').trimEnd();
                                if (!lineText) {
                                    return '';
                                }
                                const pathPart = row.path ? String(row.path) : '';
                                const lnPart = row.line_number ? `:L${row.line_number}` : '';
                                return pathPart ? `${pathPart}${lnPart} ${lineText}` : lineText;
                            })
                            .filter((line) => Boolean(line));
                        if (!traceLineStrings.length) {
                            alert('No trace lines are available yet for this identifier. Run "Initiate Analysis" first.');
                            return;
                        }
                        const model = flowUtils.buildSrvFlowModel({
                            srv: String(candidate.srv || (srvFlowFilterInput ? srvFlowFilterInput.value.trim() : '') || ''),
                            identifier: identifier,
                            trace_lines: traceLineStrings,
                        });
                        openFlowVisualTab(model, 'Visual Flow Analyzer \u00b7 SRV ' + (identifier || ''));
                    } finally {
                        visualFlowButton.disabled = false;
                        visualFlowButton.textContent = originalLabel;
                    }
                });

                actionsWrap.appendChild(downloadButton);
                actionsWrap.appendChild(initiateButton);
                actionsWrap.appendChild(visualFlowButton);
                actionsCell.appendChild(actionsWrap);
                tbody.appendChild(row);
            });

            tableWrap.appendChild(table);
            srvFlowCandidatesList.appendChild(tableWrap);
            if (srvFlowCandidatesWrap) {
                srvFlowCandidatesWrap.classList.remove('hidden');
            }
        }

        function populateTimeSelectOptions(selectElement, maxValue) {
            if (!selectElement) {
                return;
            }
            for (let value = 0; value <= maxValue; value += 1) {
                const option = document.createElement('option');
                const text = String(value).padStart(2, '0');
                option.value = text;
                option.textContent = text;
                selectElement.appendChild(option);
            }
        }

        function buildFlowFilterDateTimeValue(dateValue, hourValue, minuteValue, isEndBoundary) {
            const datePart = String(dateValue || '').trim();
            const hourPart = String(hourValue || '').trim();
            const minutePart = String(minuteValue || '').trim();

            if (!datePart) {
                return '';
            }

            let resolvedHour = hourPart;
            let resolvedMinute = minutePart;

            if (!resolvedHour) {
                resolvedHour = isEndBoundary ? '23' : '00';
            }
            if (!resolvedMinute) {
                resolvedMinute = isEndBoundary ? '59' : '00';
            }

            return `${datePart}T${resolvedHour}:${resolvedMinute}:00`;
        }

        function toDateTimeLocalValue(dateObj) {
            const year = dateObj.getFullYear();
            const month = String(dateObj.getMonth() + 1).padStart(2, '0');
            const day = String(dateObj.getDate()).padStart(2, '0');
            const hours = String(dateObj.getHours()).padStart(2, '0');
            const minutes = String(dateObj.getMinutes()).padStart(2, '0');
            return `${year}-${month}-${day}T${hours}:${minutes}`;
        }

        function appendClientTimezoneOffset(formData) {
            formData.append('client_timezone_offset_minutes', String(new Date().getTimezoneOffset()));
        }

        function appendEvtxScanDepth(formData, spaCheckValue) {
            const checkValue = String(spaCheckValue || '').trim();
            if (checkValue !== 'Check Server Connectivity Errors' && checkValue !== 'Check Event Viewer Logs') {
                return;
            }

            if (!evtxScanLimit) {
                return;
            }

            const rawValue = String(evtxScanLimit.value || '').trim();
            if (!rawValue || !/^\d+$/.test(rawValue)) {
                return;
            }

            formData.append('evtx_max_records_per_file', rawValue);
        }

        function updateEventViewerOptionVisibility() {
            const osText = String(detectedBundleOperatingSystem || '').toLowerCase();
            const isMacBundle = osText.includes('mac');

            if (spaEventViewerLabel) {
                spaEventViewerLabel.classList.toggle('hidden', isMacBundle);
            }

            if (!spaEventViewerRadio) {
                return;
            }

            spaEventViewerRadio.disabled = isMacBundle;
            if (isMacBundle && spaEventViewerRadio.checked) {
                spaEventViewerRadio.checked = false;
                toggleSpaTargetInput();
            }
        }

        populateTimeSelectOptions(spaFlowStartHour, 23);
        populateTimeSelectOptions(spaFlowEndHour, 23);
        populateTimeSelectOptions(spaFlowStartMinute, 59);
        populateTimeSelectOptions(spaFlowEndMinute, 59);

        srvFlowPresetButtons.forEach((button) => {
            button.addEventListener('click', () => {
                const minutesValue = Number(button.dataset.minutes || 0);
                if (!Number.isFinite(minutesValue) || minutesValue <= 0) {
                    return;
                }

                const endTime = new Date();
                const startTime = new Date(endTime.getTime() - (minutesValue * 60 * 1000));

                if (srvFlowStartTime) {
                    srvFlowStartTime.value = toDateTimeLocalValue(startTime);
                }
                if (srvFlowEndTime) {
                    srvFlowEndTime.value = toDateTimeLocalValue(endTime);
                }
            });
        });

        const flowUtils = window.DarthawkFlowUtils;
        if (!flowUtils) {
            throw new Error('Flow utilities failed to load.');
        }

        function renderFlowCandidates(detailsText) {
            const candidates = flowUtils.parseFlowCandidatesFromOutput(detailsText);
            const traceByPort = flowUtils.parseSelectedFlowTraceFromOutput(detailsText);
            spaFlowCandidatesList.innerHTML = '';

            async function fetchTraceLinesForSourcePort(srcPort) {
                const selectedFile = dartFile.files && dartFile.files[0] ? dartFile.files[0] : null;
                const selectedModule = document.querySelector('input[name="module"]:checked');
                const selectedZtaMode = document.querySelector('input[name="zta_access_mode"]:checked');
                const selectedSpaCheck = document.querySelector('input[name="spa_check_option"]:checked');
                const selectedEnrollmentType = document.querySelector('input[name="spa_enrollment_error_type"]:checked');
                const normalizedZtaModeValue = (
                    selectedSpaCheck && selectedSpaCheck.value === 'Check SIA Flow'
                )
                    ? 'SIA'
                    : (selectedZtaMode ? selectedZtaMode.value : '');

                if (!selectedFile || !selectedModule) {
                    return [];
                }

                const formData = new FormData();
                formData.append('file', selectedFile);
                formData.append('module', selectedModule.value);
                appendClientTimezoneOffset(formData);

                if (selectedModule.value === 'ZTA') {
                    if (normalizedZtaModeValue) {
                        formData.append('zta_access_mode', normalizedZtaModeValue);
                    }

                    if (selectedSpaCheck) {
                        formData.append('spa_check_option', selectedSpaCheck.value);
                        appendEvtxScanDepth(formData, selectedSpaCheck.value);
                        formData.append('spa_target_value', spaTargetInput.value.trim());

                        if (
                            (normalizedZtaModeValue === 'SPA' && selectedSpaCheck.value === 'Check TCP or UDP Flow')
                            || (normalizedZtaModeValue === 'SIA' && selectedSpaCheck.value === 'Check SIA Flow')
                        ) {
                            const flowFilterTimeStart = buildFlowFilterDateTimeValue(
                                spaFlowStartDate.value,
                                spaFlowStartHour.value,
                                spaFlowStartMinute.value,
                                false
                            );
                            const flowFilterTimeEnd = buildFlowFilterDateTimeValue(
                                spaFlowEndDate.value,
                                spaFlowEndHour.value,
                                spaFlowEndMinute.value,
                                true
                            );
                            formData.append('flow_selected_src_port', srcPort);
                            formData.append('flow_filter_destination_port', spaFlowDestinationPort.value.trim());
                            formData.append('flow_filter_time_start', flowFilterTimeStart);
                            formData.append('flow_filter_time_end', flowFilterTimeEnd);
                        }

                        if (
                            normalizedZtaModeValue === 'SPA'
                            && selectedSpaCheck.value === 'Check Enrollment Errors'
                            && selectedEnrollmentType
                        ) {
                            formData.append('spa_enrollment_error_type', selectedEnrollmentType.value);
                        }
                    }

                    formData.append('show_full_cached_config', showFullCachedConfig.checked ? '1' : '0');
                    formData.append('cached_config_search_term', cachedConfigSearch.value.trim());
                }

                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        body: formData,
                    });
                    const data = await response.json();
                    if (!response.ok || !data || !data.details) {
                        return [];
                    }

                    const fetchedTraceMap = flowUtils.parseSelectedFlowTraceFromOutput(data.details);
                    return fetchedTraceMap[srcPort] || [];
                } catch (error) {
                    return [];
                }
            }

            if (!candidates.length) {
                spaFlowCandidatesWrap.classList.add('hidden');
                spaFlowSummary.classList.add('hidden');
                spaFlowSummary.textContent = '';
                return;
            }

            const visualizerData = flowUtils.buildFlowVisualizerData(candidates);
            spaFlowSummary.className = 'mb-3 rounded-lg border border-sky-500/25 bg-sky-500/5 px-3 py-2 text-xs text-sky-100/90';
            spaFlowSummary.textContent = [
                `Total Matches: ${visualizerData.totalMatches}`,
                `Destinations: ${visualizerData.destinationCount}`,
                `Unique Source Ports: ${visualizerData.sourcePortCount}`,
            ].join(' | ');
            spaFlowSummary.classList.remove('hidden');

            function refreshSelectedBadge() {
                const selectedPort = spaFlowSourcePort.value.trim();
                selectedFlowCandidateSrcPort = selectedPort;
                if (selectedPort) {
                    spaFlowSelectedBadge.textContent = `Selected srcPort: ${selectedPort}`;
                    spaFlowSelectedBadge.classList.remove('hidden');
                } else {
                    spaFlowSelectedBadge.classList.add('hidden');
                    spaFlowSelectedBadge.textContent = '';
                }
            }

            visualizerData.destinationRows.forEach((destinationRow) => {
                const groupWrap = document.createElement('div');
                groupWrap.className = 'rounded-lg border border-slate-700/70 p-3 bg-black/25';

                const groupTitle = document.createElement('div');
                groupTitle.className = 'text-sky-200 text-base font-bold uppercase tracking-wider';
                groupTitle.textContent = destinationRow.destination;
                groupWrap.appendChild(groupTitle);

                const groupMeta = document.createElement('div');
                groupMeta.className = 'text-sky-200/75 text-sm md:text-base mb-2';
                const metaParts = [
                    `matches=${destinationRow.totalMatches}`,
                    `sessions=${destinationRow.sessionCount}`,
                ];
                if (destinationRow.realDestinationIp) {
                    metaParts.push(`realIp=${destinationRow.realDestinationIp}`);
                }
                groupMeta.textContent = metaParts.join(' | ');
                groupWrap.appendChild(groupMeta);

                const tableWrap = document.createElement('div');
                tableWrap.className = 'overflow-x-auto';

                const table = document.createElement('table');
                table.className = 'w-full text-sm md:text-base border border-sky-500/25 rounded-lg overflow-hidden';
                table.innerHTML = `
                    <thead class="bg-sky-900/40 text-sky-200 uppercase tracking-wider">
                        <tr>
                            <th class="text-left p-2 border-b border-sky-500/20">Source Port</th>
                            <th class="text-left p-2 border-b border-sky-500/20">Events</th>
                            <th class="text-left p-2 border-b border-sky-500/20">Timeframe</th>
                            <th class="text-left p-2 border-b border-sky-500/20">Process / Rule</th>
                            <th class="text-left p-2 border-b border-sky-500/20">Actions</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                `;

                const tableBody = table.querySelector('tbody');

                destinationRow.sessions.forEach((session) => {
                    const row = document.createElement('tr');
                    row.className = 'border-b border-sky-500/10 hover:bg-white/5';

                    const processRuleText = `${session.process || 'Unknown process'} | rule=${session.ruleType || 'Unknown'}`;
                    const timeframeText = (
                        session.firstTime
                        && session.lastTime
                        && session.firstTime !== session.lastTime
                    )
                        ? `${session.firstTime} -> ${session.lastTime}`
                        : (session.firstTime || session.lastTime || 'Unknown');
                    row.innerHTML = `
                        <td class="p-2 text-sky-100 font-bold">${session.srcPort}</td>
                        <td class="p-2 text-sky-200/90">${session.count}</td>
                        <td class="p-2 text-sky-200/90">${timeframeText}</td>
                        <td class="p-2 text-sky-200/80">${processRuleText}</td>
                        <td class="p-2 text-sky-100"></td>
                    `;

                    const actionsCell = row.lastElementChild;
                    actionsCell.className = 'p-2 text-sky-100';

                    const actionsWrap = document.createElement('div');
                    actionsWrap.className = 'flex flex-col gap-2';

                    const downloadButton = document.createElement('button');
                    downloadButton.type = 'button';
                    downloadButton.className = 'flow-download-btn rounded border border-emerald-400/40 px-2 py-1 text-sm md:text-base font-bold tracking-wide text-emerald-100 hover:bg-emerald-500/10';
                    downloadButton.textContent = 'Download Logs';
                    downloadButton.addEventListener('click', async () => {
                        const filename = `flow_${flowUtils.sanitizeFilenamePart(destinationRow.destination)}_srcPort_${flowUtils.sanitizeFilenamePart(session.srcPort)}.log`;
                        const originalLabel = downloadButton.textContent;
                        downloadButton.disabled = true;
                        downloadButton.textContent = 'Preparing...';

                        let traceLines = traceByPort[session.srcPort] || [];
                        if (!traceLines.length) {
                            traceLines = await fetchTraceLinesForSourcePort(session.srcPort);
                            if (traceLines.length) {
                                traceByPort[session.srcPort] = traceLines;
                            }
                        }

                        const cleanedTraceLines = flowUtils.cleanTraceLinesForDownload(traceLines);
                        const content = cleanedTraceLines.length
                            ? cleanedTraceLines.join(String.fromCharCode(10))
                            : flowUtils.buildSessionFallbackLogText(destinationRow.destination, session);
                        flowUtils.triggerTextDownload(
                            filename,
                            emphasizeCriticalLinesForDownload(content)
                        );

                        downloadButton.disabled = false;
                        downloadButton.textContent = originalLabel;
                    });

                    const initiateAnalysisButton = document.createElement('button');
                    initiateAnalysisButton.type = 'button';
                    initiateAnalysisButton.className = 'flow-init-analysis-btn rounded px-3 py-2 text-sm md:text-base font-bold tracking-wide';
                    initiateAnalysisButton.textContent = 'Initiate Analysis';
                    initiateAnalysisButton.addEventListener('click', () => {
                        spaFlowSourcePort.value = session.srcPort;
                        refreshSelectedBadge();
                        pendingTransactionAnalysis = {
                            srcPort: session.srcPort,
                            destination: destinationRow.destination,
                        };
                        uploadForm.requestSubmit();
                    });

                    const visualFlowButton = document.createElement('button');
                    visualFlowButton.type = 'button';
                    visualFlowButton.className = 'flow-visual-btn rounded border border-sky-400/40 px-2 py-1 text-sm md:text-base font-bold tracking-wide text-sky-100 hover:bg-sky-500/10';
                    visualFlowButton.textContent = 'Visual Flow Analyzer';
                    visualFlowButton.addEventListener('click', async () => {
                        const originalLabel = visualFlowButton.textContent;
                        visualFlowButton.disabled = true;
                        visualFlowButton.textContent = 'Building...';
                        try {
                            let traceLines = traceByPort[session.srcPort] || [];
                            if (!traceLines.length) {
                                traceLines = await fetchTraceLinesForSourcePort(session.srcPort);
                                if (traceLines.length) {
                                    traceByPort[session.srcPort] = traceLines;
                                }
                            }
                            const displayTraceLines = flowUtils.cleanTraceLinesForDisplay(traceLines);
                            const model = flowUtils.buildFlowSequenceModel(session, destinationRow, displayTraceLines);
                            openFlowVisualTab(model, 'Visual Flow Analyzer \u00b7 srcPort ' + session.srcPort);
                        } finally {
                            visualFlowButton.disabled = false;
                            visualFlowButton.textContent = originalLabel;
                        }
                    });

                    actionsWrap.appendChild(downloadButton);
                    actionsWrap.appendChild(initiateAnalysisButton);
                    actionsWrap.appendChild(visualFlowButton);
                    actionsCell.appendChild(actionsWrap);
                    tableBody.appendChild(row);
                });

                tableWrap.appendChild(table);
                groupWrap.appendChild(tableWrap);
                spaFlowCandidatesList.appendChild(groupWrap);
            });

            spaFlowSourcePort.oninput = refreshSelectedBadge;
            refreshSelectedBadge();

            spaFlowCandidatesWrap.classList.remove('hidden');
        }

        function resetOrgIdPreview() {
            orgIdPreview.classList.add('hidden');
            orgIdPreviewText.textContent = '';
        }

        function applyChatOnlyUiMode() {
            if (!CHAT_ONLY_UI_MODE) {
                return;
            }

            if (orgIdPreview) {
                orgIdPreview.classList.add('hidden');
            }
            if (moduleSelectionWrap) {
                moduleSelectionWrap.classList.add('hidden');
            }
            if (aiInsightToggleWrap) {
                aiInsightToggleWrap.classList.add('hidden');
            }
            if (duoOptions) {
                duoOptions.classList.add('hidden');
            }
            if (ztaOptions) {
                ztaOptions.classList.add('hidden');
            }
            if (spaOptions) {
                spaOptions.classList.add('hidden');
            }
            if (mainInitiateButton) {
                mainInitiateButton.classList.add('hidden');
            }
            if (analysisIndicator) {
                analysisIndicator.classList.add('hidden');
            }

            moduleRadios.forEach((radio) => {
                radio.checked = false;
                radio.required = false;
            });

            setResultOutputPanelVisibility(false);
            resetAiInsightCard();
            resetServerConnectivitySummary();
            resetConfigSyncSummary();
            resetEventViewerSummary();
            resetTndSummary();
            resetDuoPostureFlowSummary();
        }

        function splitTimestampAndTimezone(value) {
            const text = String(value || '').trim();
            if (!text || text === 'Not found') {
                return {
                    timestamp: text || 'Not found',
                    timezone: '',
                };
            }

            const match = text.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.+)$/);
            if (!match) {
                return {
                    timestamp: text,
                    timezone: '',
                };
            }

            return {
                timestamp: match[1],
                timezone: match[2],
            };
        }

        function formatLogWindow(label, logWindow) {
            if (logWindow && logWindow.skipped) {
                return `${label} Timeframe: Skipped for large bundle preview`;
            }

            const startRaw = logWindow && logWindow.start ? logWindow.start : 'Not found';
            const endRaw = logWindow && logWindow.end ? logWindow.end : 'Not found';

            const startParts = splitTimestampAndTimezone(startRaw);
            const endParts = splitTimestampAndTimezone(endRaw);

            let timezone = '';
            if (startParts.timezone && endParts.timezone) {
                timezone = startParts.timezone === endParts.timezone
                    ? startParts.timezone
                    : `${startParts.timezone} / ${endParts.timezone}`;
            } else {
                timezone = startParts.timezone || endParts.timezone || '';
            }

            const startNotFound = startParts.timestamp === 'Not found';
            const endNotFound = endParts.timestamp === 'Not found';
            if (startNotFound && endNotFound) {
                return `${label} Timeframe: Not found`;
            }

            return `${label} Timeframe: ${startParts.timestamp} -> ${endParts.timestamp}${timezone ? ` (${timezone})` : ''}`;
        }

        function toBaseVersion(versionText) {
            const text = String(versionText || '').trim();
            const match = text.match(/(\d+)\.(\d+)\.(\d+)/);
            if (!match) {
                return '';
            }
            return `${match[1]}.${match[2]}.${match[3]}`;
        }

        async function inspectSelectedBundle() {
            const selectedFile = dartFile.files[0];
            if (!selectedFile) {
                detectedBundleOperatingSystem = '';
                updateEventViewerOptionVisibility();
                resetOrgIdPreview();
                resetAgentChatCard();
                resetBundleInsightPanel();
                resetZtaSummary();
                return;
            }

            const configuredThresholdMb = Number(window.DARTHAWK_LARGE_BUNDLE_PREVIEW_THRESHOLD_MB || 1536);
            const thresholdMb = Number.isFinite(configuredThresholdMb) && configuredThresholdMb > 0
                ? configuredThresholdMb
                : 1536;
            const LARGE_BUNDLE_THRESHOLD_BYTES = thresholdMb * 1024 * 1024;
            const useLightweightInspect = selectedFile.size > LARGE_BUNDLE_THRESHOLD_BYTES;

            if (!CHAT_ONLY_UI_MODE) {
                orgIdPreview.classList.remove('hidden');
                orgIdPreviewText.textContent = useLightweightInspect
                    ? 'Scanning selected DART bundle (lightweight preview mode for large file)...'
                    : 'Scanning selected DART bundle...';
            }

            const formData = new FormData();
            formData.append('file', selectedFile);
            formData.append('include_log_windows', useLightweightInspect ? '0' : '1');
            formData.append('include_component_versions', useLightweightInspect ? '0' : '1');

            try {
                const response = await fetch('/inspect-bundle', {
                    method: 'POST',
                    body: formData
                });
                const responseContentType = (response.headers.get('content-type') || '').toLowerCase();
                let data = {};
                if (responseContentType.includes('application/json')) {
                    data = await response.json();
                } else {
                    const responseText = await response.text();
                    data = {
                        error: String(responseText || 'Unable to inspect the selected DART bundle.').trim(),
                    };
                }

                if (!response.ok) {
                    detectedBundleOperatingSystem = '';
                    updateEventViewerOptionVisibility();
                    if (!CHAT_ONLY_UI_MODE) {
                        orgIdPreviewText.textContent = data.error || 'Unable to inspect the selected DART bundle.';
                    }
                    resetAgentChatCard();
                    resetBundleInsightPanel();
                    resetZtaSummary();
                    return;
                }

                detectedBundleOperatingSystem = String(data.operating_system || '').trim();
                updateEventViewerOptionVisibility();

                const previewLines = [];
                previewLines.push(`Operating System: ${data.operating_system || 'Unknown'}`);

                const ciscoVersion = data.cisco_secure_client_version || '';
                const ztaVersion = data.zta_version || '';
                const vpnVersion = data.vpn_version || '';

                const ciscoBaseVersion = toBaseVersion(ciscoVersion);
                const ztaBaseVersion = toBaseVersion(ztaVersion);
                const vpnBaseVersion = toBaseVersion(vpnVersion);

                const resolvedBaseVersion = ciscoBaseVersion || ztaBaseVersion || vpnBaseVersion;
                previewLines.push(
                    `Cisco Secure Client Version: ${resolvedBaseVersion || 'Unknown'}`
                );

                const hasComparableBases = ztaBaseVersion && vpnBaseVersion;
                const shouldShowSeparateModuleVersions = hasComparableBases && ztaBaseVersion !== vpnBaseVersion;

                if (shouldShowSeparateModuleVersions) {
                    previewLines.push(`ZTA Version: [${ztaVersion || 'Unknown'}]`);
                    previewLines.push(`VPN Version: [${vpnVersion || 'Unknown'}]`);
                }

                if (data.org_ids && data.org_ids.length === 1) {
                    previewLines.push(`Cisco Secure Access ORG ID: ${data.org_ids[0]}`);
                } else if (data.org_ids && data.org_ids.length > 1) {
                    previewLines.push(`Cisco Secure Access ORG IDs: ${data.org_ids.join(', ')}`);
                } else {
                    previewLines.push('Cisco Secure Access ORG ID: Not found');
                }
                previewLines.push(
                    `ZTA Trace Level Logging: ${typeof data.zta_trace_level_logging_enabled === 'boolean' ? (data.zta_trace_level_logging_enabled ? 'Enabled' : 'Disabled') : 'Unknown'}`
                );

                if (data.user_ids && data.user_ids.length === 1) {
                    previewLines.push(`ZTA Enrollment User ID: ${data.user_ids[0]}`);
                } else if (data.user_ids && data.user_ids.length > 1) {
                    previewLines.push(`ZTA Enrollment User IDs: ${data.user_ids.join(', ')}`);
                } else if (data.numeric_user_ids && data.numeric_user_ids.length === 1) {
                    previewLines.push(`ZTA Enrollment User ID: ${data.numeric_user_ids[0]}`);
                } else if (data.numeric_user_ids && data.numeric_user_ids.length > 1) {
                    previewLines.push(`ZTA Enrollment User IDs: ${data.numeric_user_ids.join(', ')}`);
                } else {
                    previewLines.push('ZTA Enrollment User ID: Not found');
                }

                if (data.enrollment_methods && data.enrollment_methods.length === 1) {
                    previewLines.push(`ZTA Enrollment Method: ${data.enrollment_methods[0]}`);
                } else if (data.enrollment_methods && data.enrollment_methods.length > 1) {
                    previewLines.push(`ZTA Enrollment Methods: ${data.enrollment_methods.join(', ')}`);
                } else {
                    previewLines.push('ZTA Enrollment Method: Not found');
                }

                if (data.enrollment_times && data.enrollment_times.length === 1) {
                    previewLines.push(`ZTA Enrollment Time: ${data.enrollment_times[0]}`);
                } else if (data.enrollment_times && data.enrollment_times.length > 1) {
                    previewLines.push(`ZTA Enrollment Times: ${data.enrollment_times.join(', ')}`);
                } else {
                    previewLines.push('ZTA Enrollment Time: Not found');
                }

                previewLines.push(formatLogWindow('ZTA Logs', data.zta_logs));
                const duoUserFolders = Array.isArray(data.duo_desktop_user_folders)
                    ? data.duo_desktop_user_folders.filter((value) => String(value || '').trim())
                    : [];
                const duoDetailedEnabled = Boolean(data.duo_desktop_detailed_logging_enabled);
                previewLines.push(`Duo Detailed Diagnostics Enabled -- ${duoDetailedEnabled && duoUserFolders.length ? 'True' : 'False'}`);
                previewLines.push(formatLogWindow('Duo Desktop Logs', data.duo_logs));
                if (data.lightweight_inspect) {
                    previewLines.push('Preview Mode: Lightweight (full log-window scan skipped for speed)');
                }

                if (!CHAT_ONLY_UI_MODE) {
                    orgIdPreviewText.textContent = previewLines.join('\n');
                }

                if (data.zta_preview_signals && data.zta_preview_signals.available) {
                    lastZtaPreviewSignals = data.zta_preview_signals;
                } else {
                    lastZtaPreviewSignals = null;
                }
                syncZtaSummaryForModule();

                if (data.bundle_session_id) {
                    showAgentChatOnlyPane();
                    startAgentChatSession(data.bundle_session_id, 'Bundle Preview');
                    renderBundleInsightPanel(data, selectedFile.name);
                    if (agentChatCard) {
                        agentChatCard.classList.add('hidden');
                    }
                } else {
                    resetAgentChatCard();
                    resetBundleInsightPanel();
                }
            } catch (err) {
                detectedBundleOperatingSystem = '';
                updateEventViewerOptionVisibility();
                if (!CHAT_ONLY_UI_MODE) {
                    orgIdPreviewText.textContent = 'Unable to inspect the selected DART bundle.';
                }
                resetAgentChatCard();
                resetBundleInsightPanel();
                resetZtaSummary();
            }
        }

        function toggleSpaOptions() {
            const selectedZtaMode = document.querySelector('input[name="zta_access_mode"]:checked');
            const isSpaOrSia = selectedZtaMode && (selectedZtaMode.value === 'SPA' || selectedZtaMode.value === 'SIA');
            const isSpa = selectedZtaMode && selectedZtaMode.value === 'SPA';
            const shouldShowFullCachedConfigOption = !isSpa;

            spaOptions.classList.toggle('hidden', !isSpaOrSia);
            spaOnlyChecks.forEach((block) => {
                block.classList.toggle('hidden', !isSpa);
            });

            if (showFullCachedConfigWrap) {
                showFullCachedConfigWrap.classList.toggle('hidden', !shouldShowFullCachedConfigOption);
            }

            if (!shouldShowFullCachedConfigOption) {
                showFullCachedConfig.checked = false;
                cachedConfigSearch.value = '';
                cachedConfigSearchWrap.classList.add('hidden');
            }

            toggleCachedConfigSearch();

            if (!isSpaOrSia) {
                resetSpaFields();
                return;
            }

            if (!isSpa) {
                const selectedSpaCheck = document.querySelector('input[name="spa_check_option"]:checked');
                if (
                    selectedSpaCheck
                    && selectedSpaCheck.value !== 'Check Inclusions or Exclusions'
                    && selectedSpaCheck.value !== 'Check SIA Flow'
                    && selectedSpaCheck.value !== 'Flow Analysis'
                    && selectedSpaCheck.value !== 'Check Trusted Network Detection'
                    && selectedSpaCheck.value !== 'Check User Pause Config'
                    && selectedSpaCheck.value !== 'ZTA Health Check Detailed'
                ) {
                    selectedSpaCheck.checked = false;
                }
                spaEnrollmentTypeRadios.forEach((radio) => {
                    radio.checked = false;
                });
                spaEnrollmentTypeWrap.classList.add('hidden');
            }

            toggleSpaTargetInput();
        }

        function toggleSpaTargetInput() {
            const flowAnalysisRadio = document.getElementById('spa-check-flow-analysis');
            if (flowAnalysisRadio && flowAnalysisRadio.value !== 'Flow Analysis') {
                // Restore the unified label/value if a prior submit left it resolved.
                flowAnalysisRadio.value = 'Flow Analysis';
            }
            const selectedSpaCheck = document.querySelector('input[name="spa_check_option"]:checked');
            const selectedZtaMode = document.querySelector('input[name="zta_access_mode"]:checked');
            const isSpa = selectedZtaMode && selectedZtaMode.value === 'SPA';
            const needsTarget = selectedSpaCheck && (
                selectedSpaCheck.value === 'Check Inclusions or Exclusions'
                || selectedSpaCheck.value === 'Check SIA Flow'
                || selectedSpaCheck.value === 'Flow Analysis'
                || (isSpa && selectedSpaCheck.value === 'Check TCP or UDP Flow')
            );
            const needsFlowSourcePort = isSpa && selectedSpaCheck && selectedSpaCheck.value === 'Check TCP or UDP Flow';
            const needsFlowAnalysisPort = isSpa && selectedSpaCheck && selectedSpaCheck.value === 'Flow Analysis';
            const needsEnrollmentType = isSpa && selectedSpaCheck && selectedSpaCheck.value === 'Check Enrollment Errors';
            const needsSrvQuickAction = isSpa && selectedSpaCheck && selectedSpaCheck.value === 'SRV Check';
            const needsEvtxScanDepth = isSpa && selectedSpaCheck && (
                selectedSpaCheck.value === 'Check Server Connectivity Errors'
                || selectedSpaCheck.value === 'Check Event Viewer Logs'
            );

            spaTargetInputWrap.classList.toggle('hidden', !needsTarget);
            spaFlowSourcePortWrap.classList.toggle('hidden', !(needsFlowSourcePort || needsFlowAnalysisPort));
            spaFlowFilterWrap.classList.toggle('hidden', !needsFlowSourcePort);
            spaFlowCandidatesWrap.classList.toggle('hidden', !needsFlowSourcePort);
            spaEnrollmentTypeWrap.classList.toggle('hidden', !needsEnrollmentType);
            if (evtxScanLimitWrap) {
                evtxScanLimitWrap.classList.toggle('hidden', !needsEvtxScanDepth);
            }
            if (srvQuickActionWrap) {
                srvQuickActionWrap.classList.toggle('hidden', !needsSrvQuickAction);
            }
            if (!needsSrvQuickAction) {
                srvCheckOptionRadios.forEach((radio) => {
                    radio.checked = false;
                });
                srvConfigFilterInput.value = '';
                srvFlowFilterInput.value = '';
                if (srvFlowStartTime) {
                    srvFlowStartTime.value = '';
                }
                if (srvFlowEndTime) {
                    srvFlowEndTime.value = '';
                }
                selectedSrvFlowIdentifier = '';
            }
            toggleSrvCheckInputs();
            if (!needsTarget) {
                spaTargetInput.value = '';
                if (spaTargetInputHint) {
                    spaTargetInputHint.classList.add('hidden');
                    spaTargetInputHint.textContent = '';
                }
            }
            if (!needsFlowSourcePort && !needsFlowAnalysisPort) {
                spaFlowSourcePort.value = '';
            }
            if (!needsFlowSourcePort) {
                spaFlowDestinationPort.value = '';
                spaFlowStartDate.value = '';
                spaFlowStartHour.value = '';
                spaFlowStartMinute.value = '';
                spaFlowEndDate.value = '';
                spaFlowEndHour.value = '';
                spaFlowEndMinute.value = '';
                spaFlowCandidatesList.innerHTML = '';
                spaFlowSelectedBadge.classList.add('hidden');
                spaFlowSelectedBadge.textContent = '';
                spaFlowSummary.classList.add('hidden');
                spaFlowSummary.textContent = '';
            }

            if (!needsEnrollmentType) {
                spaEnrollmentTypeRadios.forEach((radio) => {
                    radio.checked = false;
                });
            }

            if (!needsEvtxScanDepth && evtxScanLimit) {
                evtxScanLimit.value = evtxScanLimit.defaultValue || '60000';
            }

            if (!needsTarget) {
                return;
            }

            if (selectedSpaCheck.value === 'Check Inclusions or Exclusions') {
                spaTargetInputLabel.textContent = 'Cached config Check - Enter IP or FQDN (Optional)';
                if (spaTargetInputHint) {
                    spaTargetInputHint.classList.remove('hidden');
                    spaTargetInputHint.textContent = 'If IP/FQDN is unknown, click Initiate Analysis to display SPA and SIA inclusions/exclusions.';
                }
            } else if (selectedSpaCheck.value === 'Check SIA Flow') {
                spaTargetInputLabel.textContent = 'SIA Flow - Please Enter IP or FQDN';
                if (spaTargetInputHint) {
                    spaTargetInputHint.classList.remove('hidden');
                    spaTargetInputHint.textContent = 'Press Enter in this field to run analysis immediately.';
                }
            } else if (selectedSpaCheck.value === 'Flow Analysis') {
                spaTargetInputLabel.textContent = 'Flow Analysis - Enter IP, FQDN, name, or SRV Record';
                if (spaTargetInputHint) {
                    spaTargetInputHint.classList.remove('hidden');
                    spaTargetInputHint.innerHTML = '<strong>SRV records (starting with _) run an SRV Flow; enter type=33 to list every SRV flow when you don\u2019t know the record.</strong> A partial name works too - <code>whatsapp</code> matches <code>api.whatsapp.net</code>. Otherwise the SPA/SIA flow is chosen by the selected access mode. Source port is optional. Press Enter to run.';
                }
            } else {
                spaTargetInputLabel.textContent = 'SPA Flow - Please Enter IP or FQDN';
                if (spaTargetInputHint) {
                    spaTargetInputHint.classList.remove('hidden');
                    spaTargetInputHint.textContent = 'Press Enter in this field to run analysis immediately.';
                }
            }
        }

        function toggleZtaOptions() {
            const selected = document.querySelector('input[name="module"]:checked');
            updateModuleButtonsVisibility(selected ? selected.id : '');
            syncZtaSummaryForModule();
            if (uztnaOptions) {
                uztnaOptions.classList.toggle('hidden', !(selected && selected.value === 'UZTNA'));
            }
            const isZta = selected && selected.value === 'ZTA';
            const isDuo = selected && selected.value === 'Duo Desktop';
            ztaOptions.classList.toggle('hidden', !isZta);
            if (duoOptions) {
                duoOptions.classList.toggle('hidden', !isDuo);
            }
            if (mainInitiateButton) {
                // Show the main Initiate button only once a non-ZTA module is
                // selected. It stays hidden with nothing selected (so it never
                // appears before the user picks a module) and for ZTA, which
                // uses its own contextual Initiate button.
                const showMainInitiate = !!selected && !isZta;
                mainInitiateButton.classList.toggle('hidden', !showMainInitiate);
            }
            if (!isZta) {
                ztaAccessRadios.forEach((radio) => {
                    radio.checked = false;
                });
                resetSpaFields();
                spaOptions.classList.add('hidden');
                showFullCachedConfig.checked = false;
                cachedConfigSearch.value = '';
                cachedConfigSearchWrap.classList.add('hidden');
                cachedConfigQuickActionWrap.classList.add('hidden');
                if (ztaQuickActionAnchorAfterEnrollment && cachedConfigQuickActionWrap && cachedConfigQuickActionWrap.parentElement !== ztaQuickActionAnchorAfterEnrollment) {
                    ztaQuickActionAnchorAfterEnrollment.appendChild(cachedConfigQuickActionWrap);
                }
                if (!isDuo && duoPostureFilterInput) {
                    duoPostureFilterInput.value = '';
                }
                return;
            }

            const selectedZtaMode = document.querySelector('input[name="zta_access_mode"]:checked');
            if (!selectedZtaMode) {
                const defaultSpaModeRadio = document.getElementById('zta-spa');
                if (defaultSpaModeRadio) {
                    defaultSpaModeRadio.checked = true;
                }
            }

            toggleSpaOptions();
            updateContextualInitiatePlacement();
            toggleCachedConfigSearch();
        }

        function updateModuleButtonsVisibility(selectedModuleId) {
            // Sidebar layout: keep every module visible so users can switch
            // freely. The active module is highlighted via the checked style.
            moduleLabels.forEach((label) => {
                label.classList.remove('hidden');
            });
        }

        function toggleCachedConfigSearch() {
            const shouldShow = showFullCachedConfig.checked;
            cachedConfigSearchWrap.classList.toggle('hidden', !shouldShow);

            if (!shouldShow) {
                cachedConfigSearch.value = '';
            }

            updateContextualInitiatePlacement();
        }

        function updateContextualInitiatePlacement() {
            const selectedModule = document.querySelector('input[name="module"]:checked');
            const selectedZtaMode = document.querySelector('input[name="zta_access_mode"]:checked');
            const selectedSpaCheck = document.querySelector('input[name="spa_check_option"]:checked');

            const isZta = selectedModule && selectedModule.value === 'ZTA';
            const isSpa = selectedZtaMode && selectedZtaMode.value === 'SPA';
            const shouldShowCachedConfigActionAtTop = showFullCachedConfig.checked;

            let targetAnchor = ztaQuickActionAnchorAfterEnrollment || ztaQuickActionAnchorAfterMode;
            if (shouldShowCachedConfigActionAtTop) {
                targetAnchor = cachedConfigQuickActionAnchorTop;
            } else if (isZta && isSpa) {
                targetAnchor = spaChecksQuickActionAnchor;
            }

            if (targetAnchor && cachedConfigQuickActionWrap && cachedConfigQuickActionWrap.parentElement !== targetAnchor) {
                targetAnchor.appendChild(cachedConfigQuickActionWrap);
            }

            cachedConfigQuickActionWrap.classList.toggle('hidden', !isZta);
        }

        toggleOutputSize.addEventListener('click', () => {
            const isExpanded = resultContent.classList.toggle('max-h-none');
            if (isExpanded) {
                resultContent.classList.remove('max-h-[36rem]');
                toggleOutputSize.textContent = 'Collapse Output';
            } else {
                resultContent.classList.add('max-h-[36rem]');
                toggleOutputSize.textContent = 'Expand Output';
            }
        });

        if (copyResultButton) {
            setCopyResultButtonState(false);
            copyResultButton.addEventListener('click', handleCopyResultOutput);
        }

        if (aiInsightCopyBtn) {
            aiInsightCopyBtn.addEventListener('click', async () => {
                if (!aiInsightCard || aiInsightCard.classList.contains('hidden')) {
                    return;
                }

                const content = buildAiInsightPlainText();
                if (!String(content || '').trim()) {
                    return;
                }

                if (aiInsightCopyResetTimer) {
                    clearTimeout(aiInsightCopyResetTimer);
                    aiInsightCopyResetTimer = null;
                }

                const copied = await copyTextToClipboard(content);
                aiInsightCopyBtn.textContent = copied ? 'Copied' : 'Copy Failed';

                aiInsightCopyResetTimer = window.setTimeout(() => {
                    aiInsightCopyBtn.textContent = 'Copy AI Summary';
                    aiInsightCopyResetTimer = null;
                }, 1500);
            });
        }

        if (aiInsightDownloadBtn) {
            aiInsightDownloadBtn.addEventListener('click', () => {
                if (!aiInsightCard || aiInsightCard.classList.contains('hidden')) {
                    return;
                }

                if (!latestAiInsightJson || typeof latestAiInsightJson !== 'object') {
                    return;
                }

                const jsonText = `${JSON.stringify(latestAiInsightJson, null, 2)}\n`;
                const blob = new Blob([jsonText], { type: 'application/json;charset=utf-8' });
                const objectUrl = URL.createObjectURL(blob);

                const anchor = document.createElement('a');
                anchor.href = objectUrl;
                anchor.download = 'ai_insight.json';
                document.body.appendChild(anchor);
                anchor.click();
                anchor.remove();
                URL.revokeObjectURL(objectUrl);
            });
        }

        if (agentChatForm) {
            agentChatForm.addEventListener('submit', async (event) => {
                event.preventDefault();

                if (!currentAnalysisSessionId) {
                    alert('Run an analysis first to start an agent chat session.');
                    return;
                }

                const question = agentChatInput ? String(agentChatInput.value || '').trim() : '';
                if (!question) {
                    return;
                }

                appendAgentChatMessage('user', question);
                agentChatHistory.push({ role: 'user', content: question });

                if (agentChatInput) {
                    agentChatInput.value = '';
                }

                setAgentChatBusy(true);
                setAgentChatStatus('Agent is analyzing your question...');

                try {
                    const response = await fetch('/agent-chat', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            session_id: currentAnalysisSessionId,
                            question,
                            history: agentChatHistory.slice(-10),
                        }),
                    });

                    const payload = await response.json();
                    if (!response.ok) {
                        throw new Error(String(payload && payload.error ? payload.error : 'Agent chat request failed.'));
                    }

                    const answerText = String(payload.answer_markdown || '').trim() || 'No answer returned.';
                    appendAgentChatMessage('agent', answerText);
                    agentChatHistory.push({ role: 'assistant', content: answerText });
                    setAgentChatStatus(`Answer ready | mode=${String(payload.mode || 'unknown')}`);
                } catch (error) {
                    appendAgentChatMessage('agent', `Unable to answer: ${String(error)}`);
                    setAgentChatStatus('Agent chat failed.');
                } finally {
                    setAgentChatBusy(false);
                }
            });
        }

        if (openAgentChatBtn) {
            openAgentChatBtn.addEventListener('click', () => {
                if (agentChatCard) {
                    agentChatCard.classList.remove('hidden');
                }
                if (agentChatInput) {
                    agentChatInput.focus();
                }
            });
        }

        if (resultSearchInput) {
            setResultSearchState(false);
            resultSearchInput.addEventListener('input', reRenderCurrentResultWithSearch);
            resultSearchInput.addEventListener('keydown', (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    moveToResultMatch(event.shiftKey ? -1 : 1);
                }
            });
        }

        if (clearResultSearch) {
            clearResultSearch.addEventListener('click', () => {
                if (!resultSearchInput) {
                    return;
                }
                resultSearchInput.value = '';
                reRenderCurrentResultWithSearch();
                resultSearchInput.focus();
            });
        }

        function enableToggleableRadioGroup(radios, labels, onChange, onUncheck) {
            radios.forEach((radio) => {
                const markWasChecked = () => {
                    radio.dataset.wasChecked = radio.checked ? 'true' : 'false';
                };

                radio.addEventListener('pointerdown', markWasChecked);
                radio.addEventListener('keydown', (event) => {
                    if (event.key === ' ' || event.key === 'Enter') {
                        markWasChecked();
                    }
                });

                radio.addEventListener('click', (event) => {
                    const wasChecked = radio.dataset.wasChecked === 'true';
                    radio.dataset.wasChecked = 'false';
                    if (!wasChecked) {
                        return;
                    }

                    event.preventDefault();
                    radio.checked = false;
                    if (typeof onUncheck === 'function') {
                        onUncheck(radio);
                    }
                });

                radio.addEventListener('change', () => {
                    if (typeof onChange === 'function') {
                        onChange(radio);
                    }
                });
            });

            labels.forEach((label) => {
                label.addEventListener('click', (event) => {
                    const radioId = label.getAttribute('for');
                    const relatedRadio = radioId ? document.getElementById(radioId) : null;
                    if (!relatedRadio || !relatedRadio.checked) {
                        return;
                    }

                    event.preventDefault();
                    relatedRadio.checked = false;
                    relatedRadio.dataset.wasChecked = 'false';
                    if (typeof onUncheck === 'function') {
                        onUncheck(relatedRadio);
                    }
                });
            });
        }

        enableToggleableRadioGroup(
            moduleRadios,
            moduleLabels,
            () => {
                toggleZtaOptions();
                updateResultPaneForOptionInteraction(false);
            },
            () => {
                toggleZtaOptions();
                updateResultPaneForOptionInteraction(true);
            }
        );

        enableToggleableRadioGroup(
            ztaAccessRadios,
            ztaAccessModeLabels,
            () => {
                toggleSpaOptions();
                updateResultPaneForOptionInteraction(false);
                updateContextualInitiatePlacement();
            },
            () => {
                toggleSpaOptions();
                updateResultPaneForOptionInteraction(true);
                updateContextualInitiatePlacement();
            }
        );

        enableToggleableRadioGroup(
            spaCheckRadios,
            spaCheckLabels,
            () => {
                toggleSpaTargetInput();
                updateResultPaneForOptionInteraction(false);
                updateContextualInitiatePlacement();
            },
            () => {
                toggleSpaTargetInput();
                updateResultPaneForOptionInteraction(true);
                updateContextualInitiatePlacement();
            }
        );

        enableToggleableRadioGroup(
            spaEnrollmentTypeRadios,
            spaEnrollmentTypeLabels,
            () => {
                updateContextualInitiatePlacement();
                updateResultPaneForOptionInteraction(false);
            },
            () => {
                updateContextualInitiatePlacement();
                updateResultPaneForOptionInteraction(true);
            }
        );

        enableToggleableRadioGroup(
            srvCheckOptionRadios,
            srvCheckOptionLabels,
            () => {
                toggleSrvCheckInputs();
                updateResultPaneForOptionInteraction(false);
            },
            () => {
                toggleSrvCheckInputs();
                updateResultPaneForOptionInteraction(true);
            }
        );

        showFullCachedConfig.addEventListener('change', () => {
            toggleCachedConfigSearch();
            updateResultPaneForOptionInteraction(showFullCachedConfig.checked ? false : true);
        });

        runCachedConfigSearch.addEventListener('click', () => {
            uploadForm.requestSubmit();
        });

        if (runCachedConfigAnalysis) {
            runCachedConfigAnalysis.addEventListener('click', () => {
                uploadForm.requestSubmit();
            });
        }

        if (runSpaFlowInline) {
            runSpaFlowInline.addEventListener('click', () => {
                uploadForm.requestSubmit();
            });
        }

        if (runTargetInline) {
            runTargetInline.addEventListener('click', () => {
                uploadForm.requestSubmit();
            });
        }

        if (scrollToTopBtn) {
            scrollToTopBtn.addEventListener('click', () => {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
        }

        window.addEventListener('scroll', updateScrollToTopVisibility, { passive: true });
        updateScrollToTopVisibility();

        spaTargetInput.addEventListener('input', () => {
            const selectedSpaCheck = document.querySelector('input[name="spa_check_option"]:checked');
            if (!selectedSpaCheck || selectedSpaCheck.value !== 'Check TCP or UDP Flow') {
                return;
            }
            clearSpaFlowSelectionState(true);
        });

        const flowFilterInputs = [
            spaFlowSourcePort,
            spaFlowDestinationPort,
            spaFlowStartDate,
            spaFlowStartHour,
            spaFlowStartMinute,
            spaFlowEndDate,
            spaFlowEndHour,
            spaFlowEndMinute,
            srvFlowFilterInput,
            srvFlowStartTime,
            srvFlowEndTime,
            duoPostureFilterInput,
        ];

        flowFilterInputs.forEach((input) => {
            if (!input) {
                return;
            }
            input.addEventListener('focus', clearOutputOnFlowFilterInteraction);
            input.addEventListener('input', clearOutputOnFlowFilterInteraction);
            input.addEventListener('change', clearOutputOnFlowFilterInteraction);
        });

        cachedConfigSearch.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault();
                uploadForm.requestSubmit();
            }
        });

        const submitOnEnterInputs = [
            spaTargetInput,
            spaFlowSourcePort,
            spaFlowDestinationPort,
            srvFlowFilterInput,
            srvConfigFilterInput,
            srvFlowStartTime,
            srvFlowEndTime,
            duoPostureFilterInput,
        ];

        submitOnEnterInputs.forEach((input) => {
            if (!input) {
                return;
            }
            input.addEventListener('keydown', (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    uploadForm.requestSubmit();
                }
            });
        });

        dartFile.addEventListener('change', inspectSelectedBundle);

        // "ZTA Health Check Detailed" clubs the individual functional / config
        // checks into a single click: it fires each underlying check in sequence
        // and stitches their individual reports into one stacked, detailed output.
        // The synthetic "ZTA Health Check Detailed" value is never sent to the
        // backend — only the concrete per-check values are — so no backend change
        // is required. SPA runs all four checks; SIA runs the two it supports.
        async function runZtaHealthCheckDetailed(file, moduleValue, modeValue) {
            const isSia = String(modeValue || '').toUpperCase() === 'SIA';
            // Each sub-check renders into its own dedicated visual summary card
            // (same cards the standalone buttons produce). summaryKey = the field
            // on the /analyze response, render = the card renderer for that check.
            const subChecks = isSia
                ? [
                    { value: 'Check Trusted Network Detection', title: 'Trusted Network Detection', summaryKey: 'tnd_summary', render: renderTndSummary },
                    { value: 'Check User Pause Config', title: 'User Pause Config', summaryKey: 'user_pause_summary', render: renderUserPauseSummary },
                ]
                : [
                    { value: 'Check Server Connectivity Errors', title: 'Server Connectivity Errors', summaryKey: 'server_connectivity_summary', render: renderServerConnectivitySummary },
                    { value: 'Check Configuration Sync', title: 'Configuration Sync', summaryKey: 'config_sync_summary', render: renderConfigSyncSummary },
                    { value: 'Check Trusted Network Detection', title: 'Trusted Network Detection', summaryKey: 'tnd_summary', render: renderTndSummary },
                    { value: 'Check User Pause Config', title: 'User Pause Config', summaryKey: 'user_pause_summary', render: renderUserPauseSummary },
                ];

            latestSpaCheckOption = 'ZTA Health Check Detailed';
            resultArea.classList.add('hidden');
            setResultOutputPanelVisibility(false);
            setCopyResultButtonState(false);
            setResultSearchState(false);
            setResultDownloadLinkState(false);
            setEnrollmentResultDownloadLinkState(false);
            resetServerConnectivitySummary();
            resetConfigSyncSummary();
            resetEventViewerSummary();
            resetTndSummary();
            resetUserPauseSummary();
            resetAiInsightCard();
            resetAgentChatCard();

            btnLoader.classList.remove('hidden');

            let moduleLabel = moduleValue;
            let failures = 0;
            let rendered = 0;
            const errorMessages = [];

            for (let i = 0; i < subChecks.length; i += 1) {
                const check = subChecks[i];
                const stageMsg = `Running ${check.title} (${i + 1}/${subChecks.length})...`;
                btnText.textContent = stageMsg;
                setAnalysisIndicatorState('processing', stageMsg);

                const formData = new FormData();
                formData.append('file', file);
                formData.append('module', moduleValue);
                formData.append('enable_ai_insight', '0');
                appendClientTimezoneOffset(formData);
                formData.append('zta_access_mode', isSia ? 'SIA' : 'SPA');
                formData.append('spa_check_option', check.value);
                formData.append('spa_target_value', '');
                formData.append('show_full_cached_config', '0');
                formData.append('cached_config_search_term', '');

                try {
                    const response = await fetch('/analyze', { method: 'POST', body: formData });
                    const data = await response.json();
                    if (response.ok) {
                        if (data && data.module) {
                            moduleLabel = data.module;
                        }
                        const summary = data && data[check.summaryKey];
                        if (summary) {
                            check.render(summary);
                            rendered += 1;
                        } else {
                            errorMessages.push(`${check.title}: no results found in this bundle.`);
                        }
                    } else {
                        failures += 1;
                        errorMessages.push(`${check.title}: ${(data && data.error) || ('request failed with status ' + response.status)}`);
                    }
                } catch (err) {
                    failures += 1;
                    errorMessages.push(`${check.title}: ${err.toString()}`);
                }
            }

            resultTitle.textContent = `[ ${moduleLabel} ] ZTA Health Check Detailed`;
            resultArea.classList.remove('hidden');

            if (errorMessages.length) {
                setAnalysisIndicatorState(
                    failures ? 'error' : 'success',
                    `${rendered} of ${subChecks.length} check(s) rendered. ${errorMessages.join(' ')}`
                );
            } else {
                setAnalysisIndicatorState('success', 'Analysis completed.');
            }
            btnText.textContent = 'Initiate Analysis';
            btnLoader.classList.add('hidden');
        }

        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            if (CHAT_ONLY_UI_MODE) {
                return;
            }
            
            const fileInput = document.getElementById('dartFile');
            const moduleInput = document.querySelector('input[name="module"]:checked');
            
            if(!fileInput.files[0] || !moduleInput) {
                alert('Please upload a file and select a module.');
                return;
            }

            const selectedZtaMode = document.querySelector('input[name="zta_access_mode"]:checked');
            const selectedSpaCheck = document.querySelector('input[name="spa_check_option"]:checked');

            // "ZTA Health Check Detailed" clubs several functional/config checks
            // into one click. Intercept before the normal single-check flow and
            // orchestrate the underlying checks sequentially.
            if (
                moduleInput.value === 'ZTA'
                && selectedSpaCheck
                && selectedSpaCheck.id === 'spa-check-health-detailed'
            ) {
                if (!selectedZtaMode) {
                    alert('Please select SPA or SIA for ZTA.');
                    return;
                }
                const healthMode = selectedZtaMode.value === 'SIA' ? 'SIA' : 'SPA';
                await runZtaHealthCheckDetailed(fileInput.files[0], moduleInput.value, healthMode);
                return;
            }

            // Flow Analysis: resolve the unified option into a concrete flow type
            // (SPA, SIA, or SRV) based on the entered target and selected access mode.
            // The radio's value is temporarily rewritten so all existing validation
            // and form-building logic below runs unchanged, then restored in finally.
            // Flow Analysis: resolve the unified option into a concrete flow type
            // (SPA, SIA, or SRV) based on the entered target and selected access mode.
            // Detect by stable element ID so re-submits resolve correctly even if a
            // prior submit left the radio value set to a concrete flow type. The value
            // is intentionally left resolved so downstream rendering and secondary
            // fetches see the concrete flow; toggleSpaTargetInput restores the label.
            if (selectedSpaCheck && selectedSpaCheck.id === 'spa-check-flow-analysis') {
                const flowTarget = spaTargetInput.value.trim();
                const isSiaMode = selectedZtaMode && selectedZtaMode.value === 'SIA';
                const isSrvDiscoveryToken = /^type\s*=?\s*33(\s+srv)?$/i.test(flowTarget);
                if (isSiaMode) {
                    selectedSpaCheck.value = 'Check SIA Flow';
                } else if (/^_/.test(flowTarget) || isSrvDiscoveryToken) {
                    selectedSpaCheck.value = 'SRV Check';
                    srvFlowFilterInput.value = flowTarget;
                    srvConfigFilterInput.value = '';
                } else {
                    selectedSpaCheck.value = 'Check TCP or UDP Flow';
                }
            }

            const selectedEnrollmentType = document.querySelector('input[name="spa_enrollment_error_type"]:checked');
            const wantsFullCachedConfig = showFullCachedConfig.checked;
            const normalizedZtaModeValue = (
                moduleInput.value === 'ZTA'
                && selectedSpaCheck
                && selectedSpaCheck.value === 'Check SIA Flow'
            )
                ? 'SIA'
                : (selectedZtaMode ? selectedZtaMode.value : '');

            if (moduleInput.value === 'ZTA' && !normalizedZtaModeValue && !wantsFullCachedConfig) {
                alert('Please select SPA or SIA for ZTA.');
                return;
            }

            if (
                moduleInput.value === 'ZTA'
                && normalizedZtaModeValue
                && !selectedSpaCheck
                && !wantsFullCachedConfig
            ) {
                alert('Please select one ZTA analysis check option.');
                return;
            }

            if (
                moduleInput.value === 'ZTA'
                && normalizedZtaModeValue
                && (
                    normalizedZtaModeValue === 'SPA'
                    || normalizedZtaModeValue === 'SIA'
                )
                && selectedSpaCheck
                && (
                    selectedSpaCheck.value === 'Check SIA Flow'
                    || (
                        normalizedZtaModeValue === 'SPA'
                        && selectedSpaCheck.value === 'Check TCP or UDP Flow'
                    )
                )
                && !spaTargetInput.value.trim()
            ) {
                alert('Please enter IP or FQDN for the selected check.');
                return;
            }

            if (
                moduleInput.value === 'ZTA'
                && normalizedZtaModeValue === 'SPA'
                && selectedSpaCheck
                && selectedSpaCheck.value === 'SRV Check'
                && !srvFlowFilterInput.value.trim()
                && (srvFlowStartTime && srvFlowStartTime.value || srvFlowEndTime && srvFlowEndTime.value)
            ) {
                alert('Provide SRV record filter to apply SRV Flow timeframe filters.');
                return;
            }

            if (
                moduleInput.value === 'ZTA'
                && normalizedZtaModeValue === 'SPA'
                && selectedSpaCheck
                && selectedSpaCheck.value === 'SRV Check'
                && srvFlowFilterInput.value.trim()
                && srvFlowStartTime
                && srvFlowEndTime
                && srvFlowStartTime.value
                && srvFlowEndTime.value
                && new Date(srvFlowStartTime.value).getTime() > new Date(srvFlowEndTime.value).getTime()
            ) {
                alert('SRV Flow timeframe start must be earlier than end.');
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('module', moduleInput.value);
            formData.append('enable_ai_insight', enableAiInsight && enableAiInsight.checked ? '1' : '0');
            appendClientTimezoneOffset(formData);
            if (moduleInput.value === 'UZTNA' && uztnaFlowFilterInput) {
                formData.append('uztna_filter', uztnaFlowFilterInput.value.trim());
            }
            if (moduleInput.value === 'ZTA') {
                if (normalizedZtaModeValue) {
                    formData.append('zta_access_mode', normalizedZtaModeValue);
                }
                if (selectedSpaCheck) {
                    formData.append('spa_check_option', selectedSpaCheck.value);
                    appendEvtxScanDepth(formData, selectedSpaCheck.value);
                    formData.append('spa_target_value', spaTargetInput.value.trim());
                    if (
                        (
                            normalizedZtaModeValue === 'SPA'
                            && selectedSpaCheck.value === 'Check TCP or UDP Flow'
                        )
                        || (
                            normalizedZtaModeValue === 'SIA'
                            && selectedSpaCheck.value === 'Check SIA Flow'
                        )
                    ) {
                        const flowFilterTimeStart = buildFlowFilterDateTimeValue(
                            spaFlowStartDate.value,
                            spaFlowStartHour.value,
                            spaFlowStartMinute.value,
                            false
                        );
                        const flowFilterTimeEnd = buildFlowFilterDateTimeValue(
                            spaFlowEndDate.value,
                            spaFlowEndHour.value,
                            spaFlowEndMinute.value,
                            true
                        );
                        formData.append('flow_selected_src_port', spaFlowSourcePort.value.trim());
                        formData.append('flow_filter_destination_port', spaFlowDestinationPort.value.trim());
                        formData.append('flow_filter_time_start', flowFilterTimeStart);
                        formData.append('flow_filter_time_end', flowFilterTimeEnd);
                    }
                    if (
                        normalizedZtaModeValue === 'SPA'
                        && selectedSpaCheck.value === 'Check Enrollment Errors'
                        && selectedEnrollmentType
                    ) {
                        formData.append('spa_enrollment_error_type', selectedEnrollmentType.value);
                    }
                    if (
                        normalizedZtaModeValue === 'SPA'
                        && selectedSpaCheck.value === 'SRV Check'
                    ) {
                        formData.append('srv_config_filter_value', srvConfigFilterInput.value.trim());
                        formData.append('srv_flow_filter_value', srvFlowFilterInput.value.trim());
                        formData.append('srv_flow_time_start', srvFlowStartTime ? srvFlowStartTime.value.trim() : '');
                        formData.append('srv_flow_time_end', srvFlowEndTime ? srvFlowEndTime.value.trim() : '');
                        if (selectedSrvFlowIdentifier) {
                            formData.append('srv_selected_identifier', selectedSrvFlowIdentifier);
                        }
                    }
                }
                formData.append('show_full_cached_config', showFullCachedConfig.checked ? '1' : '0');
                formData.append('cached_config_search_term', cachedConfigSearch.value.trim());
            } else if (moduleInput.value === 'Duo Desktop') {
                if (duoPostureFilterInput) {
                    formData.append('duo_posture_filter', duoPostureFilterInput.value.trim());
                }
            }

            btnText.textContent = 'Processing Payload...';
            btnLoader.classList.remove('hidden');
            setAnalysisIndicatorState('processing', 'Processing payload...');
            const isTransactionDrillDown = Boolean(pendingTransactionAnalysis || pendingSrvTransactionAnalysis);
            if (!isTransactionDrillDown) {
                resultArea.classList.add('hidden');
            }
            setCopyResultButtonState(false);
            setResultSearchState(false);
            setResultDownloadLinkState(false);
            setEnrollmentResultDownloadLinkState(false);
            setEnrollmentFlowVisualButtonState(false);
            resetEnrollmentAttempts();
            setCachedConfigDownloadLinkState(false);
            setTransactionDownloadLinkState(false);
            resetServerConnectivitySummary();
            resetDuoPostureFlowSummary();
            resetAgentChatCard();

            const isEventViewerCheck = Boolean(selectedSpaCheck) && selectedSpaCheck.value === 'Check Event Viewer Logs';
            const stageMessages = [
                'Uploading Payload...',
                'Extracting Bundle...',
                isEventViewerCheck ? 'Analyzing Event Viewer Logs (this can take up to 5 minutes)...' : 'Analyzing Logs...',
            ];
            let stageIndex = 0;
            btnText.textContent = stageMessages[stageIndex];
            setAnalysisIndicatorState('processing', stageMessages[stageIndex]);
            const processingStageTimer = window.setInterval(() => {
                stageIndex = Math.min(stageIndex + 1, stageMessages.length - 1);
                btnText.textContent = stageMessages[stageIndex];
                setAnalysisIndicatorState('processing', stageMessages[stageIndex]);
            }, 3000);

            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    latestSpaCheckOption = selectedSpaCheck ? String(selectedSpaCheck.value || '') : '';
                    const isDuoDesktopModule = moduleInput.value === 'Duo Desktop';
                    const preserveCriticalColorDownload = shouldEnableCriticalHighlight(
                        moduleInput.value,
                        normalizedZtaModeValue,
                        selectedSpaCheck ? selectedSpaCheck.value : '',
                        ''
                    );
                    const allowCriticalHighlight = !isDuoDesktopModule;

                    const hasDuoPostureFlowSummary = (
                        moduleInput.value === 'Duo Desktop'
                        && Boolean(data.duo_posture_flow_summary)
                    );
                    setResultOutputPanelVisibility(!hasDuoPostureFlowSummary);

                    if (pendingTransactionAnalysis) {
                        resultTitle.textContent = `[ ${data.module} ] Analysis Completed | Destination ${pendingTransactionAnalysis.destination} | srcPort ${pendingTransactionAnalysis.srcPort}`;
                    } else if (pendingSrvTransactionAnalysis) {
                        resultTitle.textContent = `[ ${data.module} ] Analysis Completed | SRV Identifier ${pendingSrvTransactionAnalysis.identifier}`;
                    } else if (hasDuoPostureFlowSummary) {
                        resultTitle.textContent = `[ ${data.module} ] Posture Flow Results`;
                    } else {
                        resultTitle.textContent = `[ ${data.module} ] Analysis Completed`;
                    }

                    let defaultDetailsText = data.details || JSON.stringify(data.extracted_files, null, 2);
                    renderAiInsightCard(data.ai || null);
                    startAgentChatSession(data.analysis_session_id, data.module);
                    if ((!data.ai || !data.ai.analysis_json) && data.ai && data.ai.analysis_markdown) {
                        defaultDetailsText += [
                            '',
                            '[AI Insight]',
                            String(data.ai.analysis_markdown || '').trim(),
                        ].join(String.fromCharCode(10));
                    }
                    const isEventViewerCheck = (
                        moduleInput.value === 'ZTA'
                        && normalizedZtaModeValue === 'SPA'
                        && selectedSpaCheck
                        && selectedSpaCheck.value === 'Check Event Viewer Logs'
                    );
                    const eventViewerDownloadText = (
                        isEventViewerCheck && typeof data.event_viewer_filtered_download_text === 'string'
                    )
                        ? data.event_viewer_filtered_download_text
                        : '';
                    const resolvedResultDownloadFilename = eventViewerDownloadText
                        ? String(data.event_viewer_filtered_download_filename || 'event_viewer_filtered_events.log')
                        : 'analysis_result.log';
                    const resolvedResultDownloadContent = eventViewerDownloadText || defaultDetailsText;
                    const resolvedPreserveCriticalColorDownload = eventViewerDownloadText
                        ? false
                        : preserveCriticalColorDownload;
                    setResultDownloadLinkState(
                        true,
                        resolvedResultDownloadFilename,
                        resolvedResultDownloadContent,
                        resolvedPreserveCriticalColorDownload
                    );
                    const shouldShowEnrollmentResultDownloadLink = (
                        moduleInput.value === 'ZTA'
                        && normalizedZtaModeValue === 'SPA'
                        && selectedSpaCheck
                        && selectedSpaCheck.value === 'Check Enrollment Errors'
                    );

                    if (shouldShowEnrollmentResultDownloadLink) {
                        const detectedMethod = (
                            data.enrollment_flow
                            && typeof data.enrollment_flow === 'object'
                            && data.enrollment_flow.auth_method
                        ) || 'enrollment';
                        const enrollmentType = String(detectedMethod).toLowerCase();
                        setEnrollmentResultDownloadLinkState(
                            true,
                            `enrollment_${enrollmentType}_result.log`,
                            maybeEmphasizeForDownload(defaultDetailsText, allowCriticalHighlight)
                        );
                    } else {
                        setEnrollmentResultDownloadLinkState(false);
                    }

                    const enrollmentFlowPayload = (
                        shouldShowEnrollmentResultDownloadLink
                        && data.enrollment_flow
                        && typeof data.enrollment_flow === 'object'
                        && Array.isArray(data.enrollment_flow.attempts)
                        && data.enrollment_flow.attempts.length
                    )
                        ? data.enrollment_flow
                        : null;
                    setEnrollmentFlowVisualButtonState(Boolean(enrollmentFlowPayload), enrollmentFlowPayload);
                    renderEnrollmentAttempts(enrollmentFlowPayload);

                    const shouldShowCachedConfigDownloadLink = (
                        moduleInput.value === 'ZTA'
                        && showFullCachedConfig.checked
                        && !cachedConfigSearch.value.trim()
                    );

                    if (shouldShowCachedConfigDownloadLink) {
                        setCachedConfigDownloadLinkState(
                            true,
                            'cached_config_output.log',
                            maybeEmphasizeForDownload(defaultDetailsText, allowCriticalHighlight)
                        );
                    } else {
                        setCachedConfigDownloadLinkState(false);
                    }

                    if (pendingTransactionAnalysis) {
                        const selectedPort = pendingTransactionAnalysis.srcPort;
                        const tracesByPort = flowUtils.parseSelectedFlowTraceFromOutput(defaultDetailsText);
                        let selectedTraceLines = tracesByPort[selectedPort] || [];
                        if (!selectedTraceLines.length) {
                            selectedTraceLines = await fetchTransactionTraceLinesForSourcePort(selectedPort);
                        }
                        const displayTraceLines = flowUtils.cleanTraceLinesForDisplay(selectedTraceLines);
                        const cleanedTraceLines = flowUtils.cleanTraceLinesForDownload(selectedTraceLines);
                        let transactionDisplayText = '';

                        if (displayTraceLines.length) {
                            transactionDisplayText = [
                                'Transaction Analysis',
                                `Destination: ${pendingTransactionAnalysis.destination}`,
                                `Source Port: ${selectedPort}`,
                                '',
                                ...displayTraceLines,
                            ].join(String.fromCharCode(10));
                        } else {
                            transactionDisplayText = [
                                'Transaction Analysis',
                                `Destination: ${pendingTransactionAnalysis.destination}`,
                                `Source Port: ${selectedPort}`,
                                '',
                                'No matching log lines were found for this source port in the returned trace.',
                            ].join(String.fromCharCode(10));
                        }

                        renderResultText(transactionDisplayText, allowCriticalHighlight);

                        const transactionFilename = `transaction_${flowUtils.sanitizeFilenamePart(pendingTransactionAnalysis.destination)}_srcPort_${flowUtils.sanitizeFilenamePart(selectedPort)}.log`;
                        const downloadContent = cleanedTraceLines.length
                            ? cleanedTraceLines.join(String.fromCharCode(10))
                            : transactionDisplayText;
                        setTransactionDownloadLinkState(
                            true,
                            transactionFilename,
                            maybeEmphasizeForDownload(downloadContent, allowCriticalHighlight)
                        );
                    } else if (pendingSrvTransactionAnalysis) {
                        const traceRows = Array.isArray(data.srv_selected_identifier_trace)
                            ? data.srv_selected_identifier_trace
                            : [];
                        const traceLines = traceRows
                            .map((entry) => String(entry && entry.line ? entry.line : '').trimEnd())
                            .filter((line) => Boolean(line));
                        let srvTransactionDisplayText = '';

                        if (traceLines.length) {
                            srvTransactionDisplayText = [
                                'SRV Transaction Analysis',
                                `Identifier: ${pendingSrvTransactionAnalysis.identifier}`,
                                `SRV: ${pendingSrvTransactionAnalysis.srv || srvFlowFilterInput.value.trim() || 'Unknown'}`,
                                '',
                                ...traceLines,
                            ].join(String.fromCharCode(10));
                        } else {
                            srvTransactionDisplayText = [
                                'SRV Transaction Analysis',
                                `Identifier: ${pendingSrvTransactionAnalysis.identifier}`,
                                `SRV: ${pendingSrvTransactionAnalysis.srv || srvFlowFilterInput.value.trim() || 'Unknown'}`,
                                '',
                                'No matching log lines were found for this SRV identifier in the returned trace.',
                            ].join(String.fromCharCode(10));
                        }
                        renderResultText(srvTransactionDisplayText, allowCriticalHighlight);
                        setTransactionDownloadLinkState(false);
                    } else {
                        if (hasDuoPostureFlowSummary) {
                            renderResultText('', false);
                        } else {
                            renderResultText(defaultDetailsText, allowCriticalHighlight);
                        }
                        setTransactionDownloadLinkState(false);
                    }

                    const selectedSpaCheckNow = document.querySelector('input[name="spa_check_option"]:checked');
                    const selectedZtaModeNow = document.querySelector('input[name="zta_access_mode"]:checked');
                    const shouldShowFlowCandidates = (
                        moduleInput.value === 'ZTA'
                        && selectedZtaModeNow
                        && (selectedZtaModeNow.value === 'SPA' || selectedZtaModeNow.value === 'SIA')
                        && selectedSpaCheckNow
                        && (
                            selectedSpaCheckNow.value === 'Check TCP or UDP Flow'
                            || selectedSpaCheckNow.value === 'Check SIA Flow'
                        )
                    );
                    if (shouldShowFlowCandidates) {
                        renderFlowCandidates(defaultDetailsText);
                    } else {
                        spaFlowCandidatesWrap.classList.add('hidden');
                        spaFlowCandidatesList.innerHTML = '';
                        spaFlowSelectedBadge.classList.add('hidden');
                        spaFlowSelectedBadge.textContent = '';
                        spaFlowSummary.classList.add('hidden');
                        spaFlowSummary.textContent = '';
                    }

                    const shouldShowSrvFlowCandidates = (
                        moduleInput.value === 'ZTA'
                        && selectedZtaModeNow
                        && selectedZtaModeNow.value === 'SPA'
                        && selectedSpaCheckNow
                        && selectedSpaCheckNow.value === 'SRV Check'
                        && srvFlowFilterInput.value.trim()
                    );

                    if (shouldShowSrvFlowCandidates) {
                        renderSrvFlowCandidates(data, defaultDetailsText);
                    } else if (srvFlowCandidatesWrap) {
                        srvFlowCandidatesWrap.classList.add('hidden');
                        if (srvFlowCandidatesList) {
                            srvFlowCandidatesList.innerHTML = '';
                        }
                        if (srvFlowSelectedBadge) {
                            srvFlowSelectedBadge.classList.add('hidden');
                            srvFlowSelectedBadge.textContent = '';
                        }
                        if (srvFlowSummary) {
                            srvFlowSummary.classList.add('hidden');
                            srvFlowSummary.textContent = '';
                        }
                    }

                    const shouldShowServerConnectivitySummary = (
                        moduleInput.value === 'ZTA'
                        && selectedZtaModeNow
                        && selectedZtaModeNow.value === 'SPA'
                        && selectedSpaCheckNow
                        && selectedSpaCheckNow.value === 'Check Server Connectivity Errors'
                        && data.server_connectivity_summary
                    );

                    if (shouldShowServerConnectivitySummary) {
                        renderServerConnectivitySummary(data.server_connectivity_summary);
                    } else {
                        resetServerConnectivitySummary();
                    }

                    const shouldShowConfigSyncSummary = (
                        moduleInput.value === 'ZTA'
                        && selectedZtaModeNow
                        && selectedZtaModeNow.value === 'SPA'
                        && selectedSpaCheckNow
                        && selectedSpaCheckNow.value === 'Check Configuration Sync'
                        && data.config_sync_summary
                    );

                    if (shouldShowConfigSyncSummary) {
                        renderConfigSyncSummary(data.config_sync_summary);
                        setResultOutputPanelVisibility(false);
                    } else {
                        resetConfigSyncSummary();
                    }

                    const shouldShowEventViewerSummary = (
                        moduleInput.value === 'ZTA'
                        && selectedZtaModeNow
                        && selectedZtaModeNow.value === 'SPA'
                        && selectedSpaCheckNow
                        && selectedSpaCheckNow.value === 'Check Event Viewer Logs'
                        && data.event_viewer_summary
                    );

                    if (shouldShowEventViewerSummary) {
                        const eventViewerSummaryData = Object.assign({}, data.event_viewer_summary, {
                            download_text: typeof data.event_viewer_filtered_download_text === 'string'
                                ? data.event_viewer_filtered_download_text
                                : '',
                            download_filename: data.event_viewer_filtered_download_filename
                                || data.event_viewer_summary.download_filename
                                || 'event_viewer_filtered_events.csv',
                        });
                        renderEventViewerSummary(eventViewerSummaryData);
                        setResultOutputPanelVisibility(false);
                    } else {
                        resetEventViewerSummary();
                    }

                    const shouldShowTndSummary = (
                        moduleInput.value === 'ZTA'
                        && selectedZtaModeNow
                        && (selectedZtaModeNow.value === 'SPA' || selectedZtaModeNow.value === 'SIA')
                        && selectedSpaCheckNow
                        && selectedSpaCheckNow.value === 'Check Trusted Network Detection'
                        && data.tnd_summary
                    );

                    if (shouldShowTndSummary) {
                        renderTndSummary(data.tnd_summary);
                        setResultOutputPanelVisibility(false);
                    } else {
                        resetTndSummary();
                    }

                    const shouldShowUserPauseSummary = (
                        moduleInput.value === 'ZTA'
                        && selectedZtaModeNow
                        && (selectedZtaModeNow.value === 'SPA' || selectedZtaModeNow.value === 'SIA')
                        && selectedSpaCheckNow
                        && selectedSpaCheckNow.value === 'Check User Pause Config'
                        && data.user_pause_summary
                    );

                    if (shouldShowUserPauseSummary) {
                        renderUserPauseSummary(data.user_pause_summary);
                        setResultOutputPanelVisibility(false);
                    } else {
                        resetUserPauseSummary();
                    }

                    if (moduleInput.value === 'UZTNA' && data.uztna_summary) {
                        renderUztnaSummary(data.uztna_summary);
                        setResultOutputPanelVisibility(false);
                    } else {
                        resetUztnaSummary();
                    }

                    if (moduleInput.value === 'Duo Desktop' && data.duo_posture_flow_summary) {
                        renderDuoPostureFlowSummary(data.duo_posture_flow_summary);
                    } else {
                        resetDuoPostureFlowSummary();
                    }

                    setAnalysisIndicatorState('success', 'Analysis complete. Results are ready.');
                } else {
                    setResultOutputPanelVisibility(true);
                    resultTitle.textContent = 'Analysis Failed';
                    renderResultText(data.error || 'Unknown error occurred.', moduleInput.value !== 'Duo Desktop');
                    setResultDownloadLinkState(false);
                    setEnrollmentResultDownloadLinkState(false);
                    setEnrollmentFlowVisualButtonState(false);
                    resetEnrollmentAttempts();
                    setCachedConfigDownloadLinkState(false);
                    setTransactionDownloadLinkState(false);
                    resetServerConnectivitySummary();
                    resetConfigSyncSummary();
                    resetEventViewerSummary();
                    resetTndSummary();
                    resetUserPauseSummary();
                    resetDuoPostureFlowSummary();
                    resetAiInsightCard();
                    resetAgentChatCard();
                    spaFlowCandidatesWrap.classList.add('hidden');
                    spaFlowCandidatesList.innerHTML = '';
                    spaFlowSelectedBadge.classList.add('hidden');
                    spaFlowSelectedBadge.textContent = '';
                    spaFlowSummary.classList.add('hidden');
                    spaFlowSummary.textContent = '';
                    if (srvFlowCandidatesWrap) {
                        srvFlowCandidatesWrap.classList.add('hidden');
                    }
                    if (srvFlowCandidatesList) {
                        srvFlowCandidatesList.innerHTML = '';
                    }
                    if (srvFlowSelectedBadge) {
                        srvFlowSelectedBadge.classList.add('hidden');
                        srvFlowSelectedBadge.textContent = '';
                    }
                    if (srvFlowSummary) {
                        srvFlowSummary.classList.add('hidden');
                        srvFlowSummary.textContent = '';
                    }
                    setAnalysisIndicatorState('error', 'Analysis failed. Please review the error output.');
                }
                
                resultArea.classList.remove('hidden');
                setCopyResultButtonState(String(resultContent.textContent || '').trim().length > 0);
            } catch (err) {
                setResultOutputPanelVisibility(true);
                setAnalysisIndicatorState('error', 'Request failed before completion.');
                resetAiInsightCard();
                resetAgentChatCard();
                alert('An error occurred during upload: ' + err.toString());
            } finally {
                window.clearInterval(processingStageTimer);
                pendingTransactionAnalysis = null;
                pendingSrvTransactionAnalysis = null;
                btnText.textContent = 'Initiate Analysis';
                btnLoader.classList.add('hidden');
                // NOTE: do NOT restore the radio value here. Downstream result
                // rendering and secondary fetches (candidate "Download Logs",
                // transaction drill-down) re-read input[name="spa_check_option"]
                // and need the resolved concrete flow value. The Flow Analysis
                // label/value is normalized back in toggleSpaTargetInput when the
                // user next interacts, and submit re-detects it by element ID.
            }
        });

        function buildFeedbackMailtoLink(toAddress) {
            const osValue = feedbackOs ? String(feedbackOs.value || '').trim() : '';
            const componentValue = feedbackComponent ? String(feedbackComponent.value || '').trim() : 'ZTA';
            const issueValue = feedbackIssue ? String(feedbackIssue.value || '').trim() : '';
            const srNumberValue = feedbackSrNumber ? String(feedbackSrNumber.value || '').trim() : '';
            const dartFileNameValue = feedbackDartFileName ? String(feedbackDartFileName.value || '').trim() : '';
            const evidenceFile = feedbackScreenshots && feedbackScreenshots.files && feedbackScreenshots.files[0]
                ? feedbackScreenshots.files[0]
                : null;
            const evidenceFileName = evidenceFile ? String(evidenceFile.name || '').trim() : '';

            const subject = `[DartHawk Feedback] ${componentValue || 'Unknown'} | ${osValue || 'Unknown OS'}`;
            const bodyLines = [
                'DartHawk Feedback',
                '',
                `OS: ${osValue || 'Not provided'}`,
                `Component: ${componentValue || 'Not provided'}`,
                `SR Number: ${srNumberValue || 'Not provided'}`,
                `DART File Link / Name: ${dartFileNameValue || 'Not provided'}`,
                `Evidence File: ${evidenceFileName || 'Not provided'}`,
                '',
                'Issue Description:',
                issueValue || 'Not provided',
                '',
                'Note: Please attach the selected screenshot/text file manually before sending.',
            ];

            const toValue = String(toAddress || 'amarora2@cisco.com').trim();
            return `mailto:${encodeURIComponent(toValue)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(bodyLines.join('\n'))}`;
        }

        if (feedbackForm) {
            feedbackForm.addEventListener('submit', (event) => {
                event.preventDefault();

                const osValue = feedbackOs ? String(feedbackOs.value || '').trim() : '';
                const componentValue = feedbackComponent ? String(feedbackComponent.value || '').trim() : '';
                const issueValue = feedbackIssue ? String(feedbackIssue.value || '').trim() : '';
                const srNumberValue = feedbackSrNumber ? String(feedbackSrNumber.value || '').trim() : '';
                const dartFileNameValue = feedbackDartFileName ? String(feedbackDartFileName.value || '').trim() : '';

                if (!osValue) {
                    alert('Please select OS.');
                    return;
                }
                if (!componentValue) {
                    alert('Please select component.');
                    return;
                }
                if (!issueValue) {
                    alert('Please describe the issue.');
                    return;
                }

                const selectedEvidence = feedbackScreenshots && feedbackScreenshots.files && feedbackScreenshots.files[0]
                    ? feedbackScreenshots.files[0]
                    : null;
                if (selectedEvidence) {
                    const selectedName = String(selectedEvidence.name || '').toLowerCase();
                    const selectedType = String(selectedEvidence.type || '').toLowerCase();
                    const isTextFile = selectedName.endsWith('.txt') || selectedType === 'text/plain';
                    const isImageFile = selectedType.startsWith('image/');
                    if (!isTextFile && !isImageFile) {
                        alert('Please upload only one screenshot file or one .txt file.');
                        return;
                    }
                }

                if (feedbackSubmitButton) {
                    feedbackSubmitButton.disabled = true;
                }
                if (feedbackSubmitText) {
                    feedbackSubmitText.textContent = 'Opening Email...';
                }
                const mailtoLink = buildFeedbackMailtoLink('amarora2@cisco.com');
                window.location.href = mailtoLink;

                feedbackForm.reset();
                if (feedbackComponent) {
                    feedbackComponent.value = 'ZTA';
                }
                if (feedbackPanel) {
                    feedbackPanel.classList.add('hidden');
                }

                window.setTimeout(() => {
                    if (feedbackSubmitButton) {
                        feedbackSubmitButton.disabled = false;
                    }
                    if (feedbackSubmitText) {
                        feedbackSubmitText.textContent = 'Submit Feedback';
                    }
                }, 500);
            });
        }

        applyChatOnlyUiMode();

        // ---------------------------------------------------------------
        // Modern shell: view switching, dropzone, export, history/reports
        // ---------------------------------------------------------------
        (function initDhWorkspace() {
            const HISTORY_KEY = 'darthawk_history';
            const REPORTS_KEY = 'darthawk_reports';
            const MAX_HISTORY = 15;
            const MAX_REPORTS = 20;
            const MAX_TEXT = 150000;
            const VERDICT_LABEL = { healthy: 'Healthy', degraded: 'Degraded', problem: 'Problem' };

            const readStore = (key) => {
                try { const v = JSON.parse(localStorage.getItem(key) || '[]'); return Array.isArray(v) ? v : []; }
                catch (e) { return []; }
            };
            const writeStore = (key, arr) => {
                try { localStorage.setItem(key, JSON.stringify(arr)); } catch (e) { /* quota / private mode */ }
            };
            const fmtTime = (ts) => {
                try { return new Date(ts).toLocaleString(); } catch (e) { return ''; }
            };
            const currentModule = () => {
                const r = document.querySelector('input[name="module"]:checked');
                return r ? r.value : '';
            };
            const currentOrg = () => {
                const el = document.getElementById('orgIdPreviewText');
                const m = (el ? el.textContent : '').match(/\b\d{6,}\b/);
                return m ? m[0] : '';
            };
            const currentFileName = () => {
                const f = document.getElementById('dartFile');
                return (f && f.files && f.files[0]) ? f.files[0].name : 'DART bundle';
            };
            const currentReportText = () => {
                const el = document.getElementById('resultContent');
                return el ? String(el.textContent || '') : '';
            };
            const downloadText = (name, text) => {
                const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = name;
                document.body.appendChild(a); a.click(); a.remove();
                setTimeout(() => URL.revokeObjectURL(url), 1000);
            };

            let lastAnalysis = null;

            // Called by renderZtaSummary after each ZTA snapshot render.
            window.dhRecordHistory = function (summary) {
                const record = {
                    id: 'a' + Date.now(),
                    ts: Date.now(),
                    module: currentModule() || 'ZTA',
                    org: currentOrg(),
                    file: currentFileName(),
                    verdict: summary.verdictLevel || 'healthy',
                    criticalCount: summary.criticalCount || 0,
                    warningCount: summary.warningCount || 0,
                    healthyCount: summary.healthyCount || 0,
                    total: summary.total || 0,
                    healthScore: typeof summary.healthScore === 'number' ? summary.healthScore : null,
                };
                lastAnalysis = record;
                const hist = readStore(HISTORY_KEY);
                // De-dupe: one entry per bundle (same file + org), keep newest.
                const idx = hist.findIndex((h) => h.file === record.file && h.org === record.org);
                if (idx >= 0) { hist.splice(idx, 1); }
                hist.unshift(record);
                writeStore(HISTORY_KEY, hist.slice(0, MAX_HISTORY));
                updateExportVisibility();
            };

            function updateExportVisibility() {
                const btn = document.getElementById('exportReportBtn');
                if (!btn) { return; }
                const analyzeActive = !document.getElementById('viewAnalyze').classList.contains('hidden');
                btn.classList.toggle('hidden', !(analyzeActive && lastAnalysis));
            }

            // ---- View switching ----
            const navItems = Array.from(document.querySelectorAll('.dh-rail-navitem'));
            const views = {
                analyze: document.getElementById('viewAnalyze'),
                history: document.getElementById('viewHistory'),
                reports: document.getElementById('viewReports'),
            };
            const TITLES = {
                analyze: ['DartHawk', 'Diagnostics & Reporting Tool Analyzer'],
                history: ['History', 'Previously analyzed DART bundles'],
                reports: ['Reports', 'Exported analysis reports'],
            };
            function switchView(name) {
                Object.keys(views).forEach((k) => {
                    if (views[k]) { views[k].classList.toggle('hidden', k !== name); }
                });
                navItems.forEach((n) => n.classList.toggle('is-active', n.getAttribute('data-view') === name));
                const t = TITLES[name] || TITLES.analyze;
                const titleEl = document.getElementById('dhTopbarTitle');
                const subEl = document.getElementById('dhTopbarSub');
                if (titleEl) { titleEl.textContent = t[0]; }
                if (subEl) { subEl.textContent = t[1]; }
                if (name === 'history') { renderHistory(); }
                if (name === 'reports') { renderReports(); }
                updateExportVisibility();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
            navItems.forEach((n) => n.addEventListener('click', () => switchView(n.getAttribute('data-view'))));

            // ---- History rendering ----
            function badge(verdict) {
                const span = document.createElement('span');
                span.className = `dh-record-badge is-${verdict}`;
                span.textContent = VERDICT_LABEL[verdict] || 'Healthy';
                return span;
            }
            function renderHistory() {
                const list = document.getElementById('historyList');
                const empty = document.getElementById('historyEmpty');
                const clearBtn = document.getElementById('clearHistoryBtn');
                if (!list) { return; }
                const hist = readStore(HISTORY_KEY);
                list.innerHTML = '';
                if (empty) { empty.classList.toggle('hidden', hist.length > 0); }
                if (clearBtn) { clearBtn.classList.toggle('hidden', hist.length === 0); }
                hist.forEach((h) => {
                    const row = document.createElement('div');
                    row.className = 'dh-record';
                    const main = document.createElement('div');
                    main.className = 'dh-record-main';
                    const title = document.createElement('div');
                    title.className = 'dh-record-title';
                    title.textContent = h.file || 'DART bundle';
                    const meta = document.createElement('div');
                    meta.className = 'dh-record-meta';
                    const bits = [h.module || 'ZTA'];
                    if (h.org) { bits.push('org ' + h.org); }
                    if (typeof h.healthScore === 'number') { bits.push('score ' + h.healthScore); }
                    bits.push(`${h.criticalCount} critical / ${h.warningCount} warning / ${h.healthyCount} healthy`);
                    bits.push(fmtTime(h.ts));
                    meta.textContent = bits.join('  \u00b7  ');
                    main.appendChild(title); main.appendChild(meta);
                    const actions = document.createElement('div');
                    actions.className = 'dh-record-actions';
                    const del = document.createElement('button');
                    del.type = 'button'; del.className = 'dh-topbar-btn-ghost'; del.textContent = 'Remove';
                    del.addEventListener('click', () => {
                        const next = readStore(HISTORY_KEY).filter((x) => x.id !== h.id);
                        writeStore(HISTORY_KEY, next);
                        renderHistory();
                    });
                    actions.appendChild(del);
                    row.appendChild(main); row.appendChild(badge(h.verdict)); row.appendChild(actions);
                    list.appendChild(row);
                });
            }
            const clearHistoryBtn = document.getElementById('clearHistoryBtn');
            if (clearHistoryBtn) {
                clearHistoryBtn.addEventListener('click', () => { writeStore(HISTORY_KEY, []); renderHistory(); });
            }

            // ---- Reports rendering ----
            function renderReports() {
                const list = document.getElementById('reportsList');
                const empty = document.getElementById('reportsEmpty');
                if (!list) { return; }
                const reports = readStore(REPORTS_KEY);
                list.innerHTML = '';
                if (empty) { empty.classList.toggle('hidden', reports.length > 0); }
                reports.forEach((rep) => {
                    const row = document.createElement('div');
                    row.className = 'dh-record';
                    const main = document.createElement('div');
                    main.className = 'dh-record-main';
                    const title = document.createElement('div');
                    title.className = 'dh-record-title';
                    title.textContent = rep.name || 'report.txt';
                    const meta = document.createElement('div');
                    meta.className = 'dh-record-meta';
                    const bits = [rep.module || 'ZTA'];
                    if (rep.org) { bits.push('org ' + rep.org); }
                    bits.push(fmtTime(rep.ts));
                    meta.textContent = bits.join('  \u00b7  ');
                    main.appendChild(title); main.appendChild(meta);
                    const actions = document.createElement('div');
                    actions.className = 'dh-record-actions';
                    const dl = document.createElement('button');
                    dl.type = 'button'; dl.className = 'dh-topbar-btn-ghost'; dl.textContent = 'Download';
                    dl.addEventListener('click', () => downloadText(rep.name, rep.text || ''));
                    const del = document.createElement('button');
                    del.type = 'button'; del.className = 'dh-topbar-btn-ghost'; del.textContent = 'Remove';
                    del.addEventListener('click', () => {
                        writeStore(REPORTS_KEY, readStore(REPORTS_KEY).filter((x) => x.id !== rep.id));
                        renderReports();
                    });
                    actions.appendChild(dl); actions.appendChild(del);
                    row.appendChild(main); row.appendChild(badge(rep.verdict)); row.appendChild(actions);
                    list.appendChild(row);
                });
            }

            // ---- Export ----
            function buildReportText() {
                const a = lastAnalysis || {};
                const lines = [];
                lines.push('DartHawk Analysis Report');
                lines.push('========================');
                lines.push('Generated: ' + new Date().toLocaleString());
                lines.push('Module:    ' + (a.module || currentModule() || 'ZTA'));
                if (a.org) { lines.push('Org ID:    ' + a.org); }
                lines.push('Bundle:    ' + (a.file || currentFileName()));
                if (a.verdict) {
                    lines.push('Verdict:   ' + (VERDICT_LABEL[a.verdict] || a.verdict));
                    lines.push('Summary:   ' + `${a.criticalCount || 0} critical, ${a.warningCount || 0} warning, ${a.healthyCount || 0} healthy`);
                    if (typeof a.healthScore === 'number') { lines.push('Health:    ' + a.healthScore + '/100'); }
                }
                lines.push('');
                lines.push('----- Analysis output -----');
                lines.push(currentReportText() || '(no detailed output captured)');
                return lines.join('\n');
            }
            const exportBtn = document.getElementById('exportReportBtn');
            if (exportBtn) {
                exportBtn.addEventListener('click', () => {
                    const a = lastAnalysis || {};
                    const safeFile = String(a.file || 'bundle').replace(/\.zip$/i, '').replace(/[^\w.-]+/g, '_').slice(0, 40);
                    const name = `darthawk_${safeFile || 'report'}_${new Date().toISOString().slice(0, 10)}.txt`;
                    const text = buildReportText();
                    downloadText(name, text);
                    const reports = readStore(REPORTS_KEY);
                    reports.unshift({
                        id: 'r' + Date.now(), ts: Date.now(), name: name,
                        module: a.module || currentModule() || 'ZTA', org: a.org || currentOrg(),
                        verdict: a.verdict || 'healthy', text: text.slice(0, MAX_TEXT),
                    });
                    writeStore(REPORTS_KEY, reports.slice(0, MAX_REPORTS));
                });
            }

            // ---- Drag & drop upload ----
            const dropZone = document.getElementById('dropZone');
            const dartFile = document.getElementById('dartFile');
            if (dropZone && dartFile) {
                ['dragenter', 'dragover'].forEach((ev) => dropZone.addEventListener(ev, (e) => {
                    e.preventDefault(); e.stopPropagation(); dropZone.classList.add('is-dragover');
                }));
                ['dragleave', 'dragend'].forEach((ev) => dropZone.addEventListener(ev, (e) => {
                    e.preventDefault(); e.stopPropagation(); dropZone.classList.remove('is-dragover');
                }));
                dropZone.addEventListener('drop', (e) => {
                    e.preventDefault(); e.stopPropagation(); dropZone.classList.remove('is-dragover');
                    const files = e.dataTransfer && e.dataTransfer.files;
                    if (files && files.length) {
                        const f = files[0];
                        if (!/\.zip$/i.test(f.name)) { return; }
                        try {
                            const dt = new DataTransfer();
                            dt.items.add(f);
                            dartFile.files = dt.files;
                        } catch (err) { /* older browsers */ }
                        dartFile.dispatchEvent(new Event('change', { bubbles: true }));
                    }
                });
            }
        })();

