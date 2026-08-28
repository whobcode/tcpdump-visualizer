import { parseCapture, LINKTYPE_NAMES } from "./parse/index.js";

/**
 * Report what the file actually was, rather than leaving the reader to assume.
 * Format and link type change how every byte is interpreted, and a truncated
 * capture silently showing fewer packets is worth saying out loud.
 */
function showCaptureInfo(capture) {
    const el = document.getElementById("captureInfo");
    if (!el) return;
    const bits = [
        capture.format === "pcapng" ? "pcapng" : "pcap (classic)",
        LINKTYPE_NAMES[capture.linktype] || `link type ${capture.linktype}`,
        `${capture.packets.length} packets`,
    ];
    if (capture.header?.nanos) bits.push("nanosecond timestamps");
    if (!capture.header?.littleEndian && capture.format === "pcap") bits.push("big-endian");
    if (capture.truncated) bits.push("file appears truncated");
    el.textContent = bits.join(" · ");
    el.classList.remove("hidden");
}

function showError(message) {
    const el = document.getElementById("captureError");
    if (!el) { alert("Error parsing file: " + message); return; }
    el.textContent = message;
    el.classList.remove("hidden");
    setTimeout(() => el.classList.add("hidden"), 8000);
}

let allPackets = [];
let filteredPackets = [];

const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const loadingSection = document.getElementById('loadingSection');
const resultsSection = document.getElementById('resultsSection');

// Upload area interactions
uploadArea.addEventListener('click', () => fileInput.click());

uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('dragging');
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('dragging');
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('dragging');
    const file = e.dataTransfer.files[0];
    if (file) processFile(file);
});

fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) processFile(file);
});

async function processFile(file) {
    loadingSection.classList.remove('hidden');
    resultsSection.classList.add('hidden');

    try {
        const arrayBuffer = await file.arrayBuffer();
        const capture = parseCapture(arrayBuffer);
        allPackets = capture.packets;
        filteredPackets = [...allPackets];
        showCaptureInfo(capture);
        displayResults();
    } catch (error) {
        showError(error.message);
        console.error(error);
    } finally {
        loadingSection.classList.add('hidden');
    }
}

function displayResults() {
    resultsSection.classList.remove('hidden');

    // Update stats
    updateStats();

    // Create charts
    createCharts();

    // Display packet table
    displayPacketTable();

    // Display flow diagram
    displayFlowDiagram();
}

function updateStats() {
    document.getElementById('statTotal').textContent = filteredPackets.length;

    const tcpCount = filteredPackets.filter(p => p.protocol === 'TCP').length;
    const udpCount = filteredPackets.filter(p => p.protocol === 'UDP').length;

    document.getElementById('statTCP').textContent = tcpCount;
    document.getElementById('statUDP').textContent = udpCount;

    const uniqueIPs = new Set();
    filteredPackets.forEach(p => {
        if (p.src) uniqueIPs.add(p.src);
        if (p.dst) uniqueIPs.add(p.dst);
    });
    document.getElementById('statIPs').textContent = uniqueIPs.size;
}

let charts = {};

function createCharts() {
    // Destroy existing charts
    Object.values(charts).forEach(chart => chart.destroy());
    charts = {};

    // Protocol distribution
    const protocolCounts = {};
    filteredPackets.forEach(p => {
        protocolCounts[p.protocol] = (protocolCounts[p.protocol] || 0) + 1;
    });

    charts.protocol = new Chart(document.getElementById('protocolChart'), {
        type: 'doughnut',
        data: {
            labels: Object.keys(protocolCounts),
            datasets: [{
                data: Object.values(protocolCounts),
                backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#8b5cf6']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true
        }
    });

    // Timeline
    const timeSlots = {};
    filteredPackets.forEach(p => {
        const timeKey = Math.floor(p.timestamp / 10) * 10;
        timeSlots[timeKey] = (timeSlots[timeKey] || 0) + 1;
    });

    const sortedTimes = Object.keys(timeSlots).sort((a, b) => a - b);

    charts.timeline = new Chart(document.getElementById('timelineChart'), {
        type: 'line',
        data: {
            labels: sortedTimes.map(t => new Date(t * 1000).toLocaleTimeString()),
            datasets: [{
                label: 'Packets',
                data: sortedTimes.map(t => timeSlots[t]),
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: { beginAtZero: true }
            }
        }
    });

    // Top source IPs
    const srcIPs = {};
    filteredPackets.forEach(p => {
        if (p.src) srcIPs[p.src] = (srcIPs[p.src] || 0) + 1;
    });

    const topSrcIPs = Object.entries(srcIPs)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    charts.srcIP = new Chart(document.getElementById('srcIPChart'), {
        type: 'bar',
        data: {
            labels: topSrcIPs.map(([ip]) => ip),
            datasets: [{
                label: 'Packets',
                data: topSrcIPs.map(([, count]) => count),
                backgroundColor: '#667eea'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y',
            scales: {
                x: { beginAtZero: true }
            }
        }
    });

    // Top destination ports
    const dstPorts = {};
    filteredPackets.forEach(p => {
        if (p.dstPort) dstPorts[p.dstPort] = (dstPorts[p.dstPort] || 0) + 1;
    });

    const topDstPorts = Object.entries(dstPorts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    charts.dstPort = new Chart(document.getElementById('dstPortChart'), {
        type: 'bar',
        data: {
            labels: topDstPorts.map(([port]) => port),
            datasets: [{
                label: 'Packets',
                data: topDstPorts.map(([, count]) => count),
                backgroundColor: '#764ba2'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}

function displayPacketTable() {
    const tbody = document.getElementById('packetTable');
    tbody.innerHTML = '';

    const displayPackets = filteredPackets.slice(0, 100);

    displayPackets.forEach(packet => {
        const row = tbody.insertRow();
        row.innerHTML = `
            <td>${packet.num}</td>
            <td>${packet.time}</td>
            <td>${packet.src}${packet.srcPort ? ':' + packet.srcPort : ''}</td>
            <td>${packet.dst}${packet.dstPort ? ':' + packet.dstPort : ''}</td>
            <td class="protocol-${packet.protocol.toLowerCase()}">${packet.protocol}</td>
            <td>${packet.length}</td>
            <td>${packet.info}</td>
        `;
    });

    if (filteredPackets.length > 100) {
        const row = tbody.insertRow();
        row.innerHTML = `<td colspan="7" style="text-align: center; color: #666; font-style: italic;">
            Showing first 100 of ${filteredPackets.length} packets
        </td>`;
    }
}

function displayFlowDiagram() {
    const flowContainer = document.getElementById('flowDiagram');
    flowContainer.innerHTML = '';

    const flows = {};
    filteredPackets.forEach(p => {
        if (p.src && p.dst) {
            const flowKey = `${p.src}:${p.srcPort || '*'} → ${p.dst}:${p.dstPort || '*'} (${p.protocol})`;
            flows[flowKey] = (flows[flowKey] || 0) + 1;
        }
    });

    const topFlows = Object.entries(flows)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20);

    topFlows.forEach(([flow, count]) => {
        const [src, dst, protocol] = flow.match(/([^→]+)→([^(]+)\(([^)]+)\)/).slice(1);

        const flowItem = document.createElement('div');
        flowItem.className = 'flow-item';
        flowItem.innerHTML = `
            <div class="flow-src">${src.trim()}</div>
            <div class="flow-arrow">→</div>
            <div class="flow-dst">${dst.trim()}</div>
            <div class="flow-info">${protocol.trim()} • ${count} packets</div>
        `;
        flowContainer.appendChild(flowItem);
    });
}

// Filtering
document.getElementById('applyFilter').addEventListener('click', applyFilters);
document.getElementById('clearFilter').addEventListener('click', () => {
    document.getElementById('filterIP').value = '';
    document.getElementById('filterPort').value = '';
    document.getElementById('filterProtocol').value = '';
    applyFilters();
});

function applyFilters() {
    const ipFilter = document.getElementById('filterIP').value.toLowerCase();
    const portFilter = document.getElementById('filterPort').value;
    const protocolFilter = document.getElementById('filterProtocol').value;

    filteredPackets = allPackets.filter(packet => {
        if (ipFilter && !packet.src.includes(ipFilter) && !packet.dst.includes(ipFilter)) {
            return false;
        }
        if (portFilter && packet.srcPort != portFilter && packet.dstPort != portFilter) {
            return false;
        }
        if (protocolFilter && packet.protocol !== protocolFilter) {
            return false;
        }
        return true;
    });

    displayResults();
}
