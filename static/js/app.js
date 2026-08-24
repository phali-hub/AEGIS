const state = { activeTab: 'dashboard' };

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

document.addEventListener('DOMContentLoaded', () => {
    checkConfig();
    bindNav();
    bindIPLookup();
    bindURLScan();
    bindEmailAnalysis();
    showTab('dashboard');
});

async function checkConfig() {
    try {
        const r = await fetch('/api/config-status');
        const d = await r.json();
        for (const [k, v] of Object.entries(d)) {
            const el = $(`#dot-${k}`);
            if (el) { el.className = `api-dot ${v ? 'on' : 'off'}`; }
        }
        const missing = Object.entries(d).filter(([,v]) => !v).map(([k]) => k);
        const notice = $('#config-notice');
        if (notice && missing.length) {
            notice.innerHTML = `⚠ Configure API keys in <code>.env</code> file: <code>${missing.join('</code>, <code>')}</code>`;
            notice.style.display = 'block';
        } else if (notice) {
            notice.style.display = 'none';
        }
    } catch (e) { console.error('Config check failed:', e); }
}

function bindNav() {
    $$('.nav-item').forEach(el => {
        el.addEventListener('click', () => {
            const tab = el.dataset.tab;
            if (tab) showTab(tab);
        });
    });
}

function showTab(tab) {
    state.activeTab = tab;
    $$('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.tab === tab));
    $$('.tab-content').forEach(el => el.classList.toggle('active', el.id === `tab-${tab}`));
    const h2 = document.querySelector('.topbar h2');
    const labels = { dashboard: '📊 Dashboard', ip: '🖥 IP Lookup', url: '🔗 URL Scan', email: '📧 Email Analysis' };
    if (h2) h2.textContent = labels[tab] || 'Dashboard';
}

/* ── Loading state ──────────────────────────── */
function setLoading(id, loading) {
    const container = document.getElementById(id);
    if (!container) return;
    if (loading) {
        container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Analyzing...</span></div>`;
    }
}

function setError(id, msg) {
    const container = document.getElementById(id);
    if (container) {
        container.innerHTML = `<div style="color:var(--danger);padding:16px;font-size:13px;">⚠ ${msg}</div>`;
    }
}

/* ── IP Lookup ──────────────────────────────── */
function bindIPLookup() {
    const btn = $('#btn-lookup-ip');
    const input = $('#input-ip');
    if (!btn) return;
    btn.addEventListener('click', lookupIP);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') lookupIP(); });
}

async function lookupIP() {
    const ip = $('#input-ip').value.trim();
    if (!ip) return;
    const container = $('#ip-result');
    setLoading(container, true);
    try {
        const r = await fetch('/api/check-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        const d = await r.json();
        if (d.error) { setError(container, d.error); return; }
        renderIPResult(container, d);
    } catch (e) { setError(container, 'Network error: ' + e.message); }
}

function renderIPResult(container, d) {
    const intel = d.intel || {};
    const score = intel.abuse_score || 0;
    const color = score >= 80 ? 'var(--danger)' : score >= 30 ? 'var(--warning)' : 'var(--success)';
    const label = score >= 80 ? 'MALICIOUS' : score >= 30 ? 'SUSPICIOUS' : 'CLEAN';
    const badgeCls = score >= 80 ? 'badge-malicious' : score >= 30 ? 'badge-suspicious' : 'badge-clean';

    let reportsHtml = '';
    if (intel.reports && intel.reports.length) {
        reportsHtml = intel.reports.slice(0, 5).map(r =>
            `<div class="result-row"><span>${r.comment || 'No comment'}</span><span style="color:var(--text-muted)">${r.reportedAt ? r.reportedAt.slice(0,10) : ''}</span></div>`
        ).join('');
    }

    container.innerHTML = `
        <div class="card">
            <div class="card-header"><span class="card-title"><span class="icon">🖥</span> IP Intelligence</span></div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                <div>
                    <div style="font-size:18px;font-weight:700;font-family:var(--font-mono);">${intel.ip || 'N/A'}</div>
                    <div style="font-size:12px;color:var(--text-muted);">${intel.country || ''}${intel.isp ? ' · ' + intel.isp : ''}</div>
                </div>
                <span class="badge ${badgeCls}">${label} · ${score}/100</span>
            </div>
            <div class="score-bar"><div class="score-bar-fill" style="width:${score}%;background:${color};"></div></div>
            <div class="grid-2" style="margin-top:12px;">
                ${renderKV('Total Reports', intel.total_reports)}
                ${renderKV('Last Reported', intel.last_reported ? intel.last_reported.slice(0,10) : '—')}
                ${renderKV('Usage Type', intel.usage_type || '—')}
                ${renderKV('Domain', intel.domain || '—')}
                ${renderKV('Whitelisted', intel.is_whitelisted ? 'Yes' : 'No')}
                ${renderKV('Public', intel.is_public ? 'Yes' : 'No')}
            </div>
            ${reportsHtml ? `<div style="margin-top:12px;"><div class="result-key">Recent Reports</div>${reportsHtml}</div>` : ''}
        </div>
        ${d.ai_analysis ? renderAI(d.ai_analysis) : ''}
    `;
}

/* ── URL Scan ───────────────────────────────── */
function bindURLScan() {
    const btn = $('#btn-scan-url');
    const input = $('#input-url');
    if (!btn) return;
    btn.addEventListener('click', scanURL);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') scanURL(); });
}

async function scanURL() {
    const url = $('#input-url').value.trim();
    if (!url) return;
    const container = $('#url-result');
    setLoading(container, true);
    try {
        const r = await fetch('/api/scan-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const d = await r.json();
        if (d.error) { setError(container, d.error); return; }
        renderURLResult(container, d);
    } catch (e) { setError(container, 'Network error: ' + e.message); }
}

function renderURLResult(container, d) {
    const vt = d.virustotal || {};
    const uh = d.urlhaus || {};

    const vtMal = vt.malicious || 0;
    const vtSus = vt.suspicious || 0;
    const vtTotal = vt.total || 1;
    const vtScore = vtTotal > 0 ? Math.round((vtMal + vtSus) / vtTotal * 100) : 0;
    const vtColor = vtMal > 0 ? 'var(--danger)' : vtSus > 0 ? 'var(--warning)' : vtScore > 0 ? 'var(--text-muted)' : 'var(--success)';

    const urlhausFound = uh.found;
    const urlhausThreat = uh.threat || (urlhausFound ? 'Listed' : 'Not found');

    let vtEnginesHtml = '';
    if (vt.malicious_engines && vt.malicious_engines.length) {
        vtEnginesHtml = vt.malicious_engines.map(e =>
            `<span class="badge badge-malicious" style="margin:2px;">${e.engine}: ${e.result}</span>`
        ).join(' ');
    }

    container.innerHTML = `
        <div class="card">
            <div class="card-header"><span class="card-title"><span class="icon">🔗</span> VirusTotal Scan</span></div>
            <div style="font-size:13px;font-family:var(--font-mono);word-break:break-all;margin-bottom:12px;">${vt.url || 'N/A'}</div>
            <div class="grid-3" style="margin-bottom:12px;">
                <div class="stat-card"><div class="stat-value" style="color:var(--danger)">${vtMal}</div><div class="stat-label">Malicious</div></div>
                <div class="stat-card"><div class="stat-value" style="color:var(--warning)">${vtSus}</div><div class="stat-label">Suspicious</div></div>
                <div class="stat-card"><div class="stat-value" style="color:var(--success)">${vt.harmless || 0}</div><div class="stat-label">Harmless</div></div>
            </div>
            ${vtEnginesHtml ? `<div style="margin-bottom:8px;">${vtEnginesHtml}</div>` : ''}
            ${vt.error ? `<div style="color:var(--danger);font-size:12px;margin-top:8px;">⚠ ${vt.error}</div>` : ''}
        </div>

        <div class="card">
            <div class="card-header"><span class="card-title"><span class="icon">☠</span> URLhaus Report</span></div>
            <div style="display:flex;gap:12px;align-items:center;">
                <span class="badge ${urlhausFound ? 'badge-malicious' : 'badge-clean'}">${urlhausFound ? 'THREAT FOUND' : 'CLEAN'}</span>
                <span style="font-size:13px;">${urlhausThreat}</span>
            </div>
            ${uh.tags && uh.tags.length ? `<div style="margin-top:8px;">${uh.tags.map(t => `<span class="badge badge-info" style="margin:2px;">${t}</span>`).join(' ')}</div>` : ''}
            <div class="grid-2" style="margin-top:12px;">
                ${renderKV('Status', uh.status || '—')}
                ${renderKV('Date Added', uh.date_added || '—')}
                ${renderKV('Reporter', uh.reporter || '—')}
                ${uh.reference ? `<div><div class="result-key">Reference</div><div class="result-value" style="color:var(--blue);font-size:12px;">${uh.reference}</div></div>` : ''}
            </div>
            ${uh.error ? `<div style="color:var(--danger);font-size:12px;margin-top:8px;">⚠ ${uh.error}</div>` : ''}
        </div>
        ${d.ai_analysis ? renderAI(d.ai_analysis) : ''}
    `;
}

/* ── Email Analysis ─────────────────────────── */
function bindEmailAnalysis() {
    const btn = $('#btn-analyze-email');
    if (!btn) return;
    btn.addEventListener('click', analyzeEmail);
}

async function analyzeEmail() {
    const raw = $('#input-email').value.trim();
    if (!raw) return;
    const container = $('#email-result');
    setLoading(container, true);
    try {
        const r = await fetch('/api/analyze-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ raw_email: raw })
        });
        const d = await r.json();
        if (d.error) { setError(container, d.error); return; }
        renderEmailResult(container, d);
    } catch (e) { setError(container, 'Network error: ' + e.message); }
}

function renderEmailResult(container, d) {
    const p = d.parsed || {};
    const score = p.phishing_score || 0;
    const verdict = p.verdict || 'clean';
    const verdictColor = verdict === 'malicious' ? 'var(--danger)' : verdict === 'suspicious' ? 'var(--warning)' : 'var(--success)';
    const badgeCls = verdict === 'malicious' ? 'badge-malicious' : verdict === 'suspicious' ? 'badge-suspicious' : 'badge-clean';

    const headers = p.headers || {};
    const auth = p.auth_results || {};

    let indicatorsHtml = '';
    if (p.phishing_indicators && p.phishing_indicators.length) {
        indicatorsHtml = p.phishing_indicators.map(ind => {
            const sevColor = ind.severity === 'high' ? 'var(--danger)' : ind.severity === 'medium' ? 'var(--warning)' : 'var(--text-muted)';
            return `<div class="indicator-item"><span class="dot" style="background:${sevColor}"></span>${ind.indicator}${ind.score ? ` <span style="color:var(--text-muted)">(+${ind.score})</span>` : ''}</div>`;
        }).join('');
    }

    container.innerHTML = `
        <div class="card">
            <div class="card-header">
                <span class="card-title"><span class="icon">📧</span> Email Analysis</span>
                <span class="badge ${badgeCls}">${verdict.toUpperCase()} · ${score}/100</span>
            </div>
            <div class="score-bar"><div class="score-bar-fill" style="width:${score}%;background:${verdictColor};"></div></div>

            <div style="margin:12px 0;">
                <div class="result-row"><span class="result-key">From</span><span class="result-value">${headers.From || '—'}</span></div>
                <div class="result-row"><span class="result-key">To</span><span class="result-value">${headers.To || '—'}</span></div>
                <div class="result-row"><span class="result-key">Subject</span><span class="result-value">${headers.Subject || '—'}</span></div>
                <div class="result-row"><span class="result-key">Date</span><span class="result-value">${headers.Date || '—'}</span></div>
                ${headers['Reply-To'] ? `<div class="result-row"><span class="result-key">Reply-To</span><span class="result-value">${headers['Reply-To']}</span></div>` : ''}
            </div>

            ${Object.keys(auth).length ? `<div style="margin:12px 0;">
                <div class="result-key" style="margin-bottom:4px;">Authentication Results</div>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    ${Object.entries(auth).map(([k,v]) => {
                        const c = v === 'fail' ? 'badge-malicious' : v === 'pass' ? 'badge-clean' : 'badge-info';
                        return `<span class="badge ${c}">${k.toUpperCase()}: ${v}</span>`;
                    }).join('')}
                </div>
            </div>` : ''}

            ${indicatorsHtml ? `<div style="margin:12px 0;">
                <div class="result-key" style="margin-bottom:4px;">Phishing Indicators (Score: ${score}/100)</div>
                ${indicatorsHtml}
            </div>` : ''}

            ${p.urls && p.urls.length ? `<div style="margin:12px 0;">
                <div class="result-key">URLs Found (${p.urls.length})</div>
                <div style="max-height:150px;overflow-y:auto;background:var(--bg-input);padding:8px;border-radius:4px;font-size:11px;font-family:var(--font-mono);">
                    ${p.urls.map(u => `<div style="padding:2px 0;word-break:break-all;">${u}</div>`).join('')}
                </div>
            </div>` : ''}

            ${p.attachments && p.attachments.length ? `<div style="margin:12px 0;">
                <div class="result-key">Attachments</div>
                ${p.attachments.map(a => `<span class="badge badge-info" style="margin:2px;">${a}</span>`).join(' ')}
            </div>` : ''}

            ${p.body_preview ? `<div style="margin:12px 0;">
                <div class="result-key">Body Preview</div>
                <div style="background:var(--bg-input);padding:10px;border-radius:4px;font-size:12px;font-family:var(--font-mono);max-height:150px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:var(--text-muted);">${escapeHtml(p.body_preview)}</div>
            </div>` : ''}
        </div>
        ${d.ai_analysis ? renderAI(d.ai_analysis) : ''}
    `;
}

/* ── Shared ─────────────────────────────────── */
function renderKV(key, value) {
    const v = value !== null && value !== undefined ? value : '—';
    return `<div><div class="result-key">${key}</div><div class="result-value">${v}</div></div>`;
}

function renderAI(text) {
    const formatted = text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/\n/g, '<br>')
        .replace(/- (.*?)(<br>|$)/g, '• $1<br>');
    return `
        <div class="ai-box">
            <div class="ai-header">🧠 AI Threat Analysis · llama-3.3-70b</div>
            <div class="ai-content">${formatted}</div>
        </div>
    `;
}

function escapeHtml(text) {
    const d = document.createElement('div');
    d.textContent = text;
    return d.innerHTML;
}
