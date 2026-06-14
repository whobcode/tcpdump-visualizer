// src/index.js
var index_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/" || url.pathname === "/index.html") {
      return new Response(HTML_CONTENT, {
        headers: { "Content-Type": "text/html" }
      });
    }
    return new Response("Not Found", { status: 404 });
  }
};
var HTML_CONTENT = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TCP Dump Visualizer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }

        h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }

        .subtitle {
            font-size: 1.1rem;
            opacity: 0.9;
        }

        .upload-section {
            background: white;
            border-radius: 15px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }

        .upload-area {
            border: 3px dashed #667eea;
            border-radius: 10px;
            padding: 50px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .upload-area:hover {
            border-color: #764ba2;
            background: #f8f9ff;
        }

        .upload-area.dragging {
            background: #f0f4ff;
            border-color: #764ba2;
        }

        .upload-icon {
            font-size: 4rem;
            margin-bottom: 20px;
        }

        .upload-text {
            font-size: 1.2rem;
            color: #333;
            margin-bottom: 10px;
        }

        .upload-subtext {
            color: #666;
            font-size: 0.9rem;
        }

        #fileInput {
            display: none;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .stat-label {
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }

        .charts-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .chart-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .chart-title {
            font-size: 1.2rem;
            margin-bottom: 20px;
            color: #333;
            font-weight: 600;
        }

        .table-container {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
        }

        tr:hover {
            background: #f8f9ff;
        }

        .protocol-tcp { color: #10b981; font-weight: 600; }
        .protocol-udp { color: #3b82f6; font-weight: 600; }
        .protocol-icmp { color: #f59e0b; font-weight: 600; }
        .protocol-other { color: #6b7280; font-weight: 600; }

        .filter-section {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .filter-group {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .filter-input {
            padding: 10px 15px;
            border: 2px solid #e5e7eb;
            border-radius: 5px;
            font-size: 0.9rem;
            flex: 1;
            min-width: 200px;
        }

        .filter-input:focus {
            outline: none;
            border-color: #667eea;
        }

        .btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .btn:hover {
            background: #764ba2;
            transform: translateY(-2px);
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #667eea;
            font-size: 1.2rem;
        }

        .hidden {
            display: none;
        }

        .flow-diagram {
            margin-top: 20px;
        }

        .flow-item {
            display: flex;
            align-items: center;
            padding: 10px;
            margin: 5px 0;
            background: #f8f9ff;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }

        .flow-src, .flow-dst {
            flex: 1;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }

        .flow-arrow {
            margin: 0 15px;
            color: #667eea;
            font-weight: bold;
        }

        .flow-info {
            flex: 1;
            font-size: 0.85rem;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>\u{1F310} TCP Dump Visualizer</h1>
            <p class="subtitle">Analyze and visualize your network captures</p>
        </header>

        <div class="upload-section">
            <div class="upload-area" id="uploadArea">
                <div class="upload-icon">\u{1F4C1}</div>
                <div class="upload-text">Drop your PCAP file here or click to browse</div>
                <div class="upload-subtext">Supports .pcap and .pcapng files</div>
                <input type="file" id="fileInput" accept=".pcap,.pcapng,.cap">
            </div>
        </div>

        <div id="loadingSection" class="loading hidden">
            <div>\u23F3 Parsing capture file...</div>
        </div>

        <div id="resultsSection" class="hidden">
            <div class="filter-section">
                <div class="filter-group">
                    <input type="text" class="filter-input" id="filterIP" placeholder="Filter by IP address...">
                    <input type="text" class="filter-input" id="filterPort" placeholder="Filter by port...">
                    <select class="filter-input" id="filterProtocol" style="flex: 0 0 150px;">
                        <option value="">All Protocols</option>
                        <option value="TCP">TCP</option>
                        <option value="UDP">UDP</option>
                        <option value="ICMP">ICMP</option>
                    </select>
                    <button class="btn" id="applyFilter">Apply Filters</button>
                    <button class="btn" id="clearFilter">Clear</button>
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Total Packets</div>
                    <div class="stat-value" id="statTotal">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">TCP Packets</div>
                    <div class="stat-value" id="statTCP">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">UDP Packets</div>
                    <div class="stat-value" id="statUDP">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Unique IPs</div>
                    <div class="stat-value" id="statIPs">0</div>
                </div>
            </div>

            <div class="charts-container">
                <div class="chart-card">
                    <div class="chart-title">Protocol Distribution</div>
                    <canvas id="protocolChart"></canvas>
                </div>
                <div class="chart-card">
                    <div class="chart-title">Packet Timeline</div>
                    <canvas id="timelineChart"></canvas>
                </div>
                <div class="chart-card">
                    <div class="chart-title">Top Source IPs</div>
                    <canvas id="srcIPChart"></canvas>
                </div>
                <div class="chart-card">
                    <div class="chart-title">Top Destination Ports</div>
                    <canvas id="dstPortChart"></canvas>
                </div>
            </div>

            <div class="chart-card">
                <div class="chart-title">Connection Flows (Top 20)</div>
                <div class="flow-diagram" id="flowDiagram"></div>
            </div>

            <div class="table-container">
                <div class="chart-title">Packet Details</div>
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>Length</th>
                            <th>Info</th>
                        </tr>
                    </thead>
                    <tbody id="packetTable"></tbody>
                </table>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"><\/script>
    <script>
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
                allPackets = parsePcap(arrayBuffer);
                filteredPackets = [...allPackets];
                displayResults();
            } catch (error) {
                alert('Error parsing file: ' + error.message);
                console.error(error);
            } finally {
                loadingSection.classList.add('hidden');
            }
        }

        function parsePcap(buffer) {
            const view = new DataView(buffer);
            let offset = 0;

            // Read global header (24 bytes)
            const magicNumber = view.getUint32(offset, true);
            offset += 24;

            const packets = [];
            let packetNum = 0;

            // Parse packets
            while (offset < buffer.byteLength - 16) {
                try {
                    // Packet header (16 bytes)
                    const tsSec = view.getUint32(offset, true);
                    const tsUsec = view.getUint32(offset + 4, true);
                    const inclLen = view.getUint32(offset + 8, true);
                    const origLen = view.getUint32(offset + 12, true);
                    offset += 16;

                    if (inclLen > buffer.byteLength - offset) break;

                    const packetData = new Uint8Array(buffer, offset, inclLen);
                    const packet = parsePacketData(packetData, tsSec, tsUsec, packetNum++);
                    packets.push(packet);

                    offset += inclLen;
                } catch (e) {
                    console.error('Error parsing packet:', e);
                    break;
                }
            }

            return packets;
        }

        function parsePacketData(data, tsSec, tsUsec, num) {
            const packet = {
                num,
                timestamp: tsSec + (tsUsec / 1000000),
                time: new Date((tsSec + tsUsec / 1000000) * 1000).toLocaleTimeString(),
                length: data.length,
                protocol: 'Unknown',
                src: '',
                dst: '',
                srcPort: '',
                dstPort: '',
                info: ''
            };

            // Skip Ethernet header (14 bytes)
            if (data.length < 14) return packet;

            const etherType = (data[12] << 8) | data[13];

            // IPv4
            if (etherType === 0x0800 && data.length >= 34) {
                const ipHeaderLen = (data[14] & 0x0F) * 4;
                const protocol = data[23];

                packet.src = \`\${data[26]}.\${data[27]}.\${data[28]}.\${data[29]}\`;
                packet.dst = \`\${data[30]}.\${data[31]}.\${data[32]}.\${data[33]}\`;

                const ipDataStart = 14 + ipHeaderLen;

                // TCP
                if (protocol === 6 && data.length >= ipDataStart + 4) {
                    packet.protocol = 'TCP';
                    packet.srcPort = (data[ipDataStart] << 8) | data[ipDataStart + 1];
                    packet.dstPort = (data[ipDataStart + 2] << 8) | data[ipDataStart + 3];

                    const flags = data[ipDataStart + 13];
                    const flagStrs = [];
                    if (flags & 0x02) flagStrs.push('SYN');
                    if (flags & 0x10) flagStrs.push('ACK');
                    if (flags & 0x01) flagStrs.push('FIN');
                    if (flags & 0x04) flagStrs.push('RST');
                    if (flags & 0x08) flagStrs.push('PSH');

                    packet.info = flagStrs.join(', ');
                }
                // UDP
                else if (protocol === 17 && data.length >= ipDataStart + 4) {
                    packet.protocol = 'UDP';
                    packet.srcPort = (data[ipDataStart] << 8) | data[ipDataStart + 1];
                    packet.dstPort = (data[ipDataStart + 2] << 8) | data[ipDataStart + 3];
                    const udpLen = (data[ipDataStart + 4] << 8) | data[ipDataStart + 5];
                    packet.info = \`Len=\${udpLen}\`;
                }
                // ICMP
                else if (protocol === 1) {
                    packet.protocol = 'ICMP';
                    if (data.length >= ipDataStart + 2) {
                        const icmpType = data[ipDataStart];
                        const icmpCode = data[ipDataStart + 1];
                        packet.info = \`Type=\${icmpType} Code=\${icmpCode}\`;
                    }
                }
            }

            return packet;
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
                row.innerHTML = \`
                    <td>\${packet.num}</td>
                    <td>\${packet.time}</td>
                    <td>\${packet.src}\${packet.srcPort ? ':' + packet.srcPort : ''}</td>
                    <td>\${packet.dst}\${packet.dstPort ? ':' + packet.dstPort : ''}</td>
                    <td class="protocol-\${packet.protocol.toLowerCase()}">\${packet.protocol}</td>
                    <td>\${packet.length}</td>
                    <td>\${packet.info}</td>
                \`;
            });

            if (filteredPackets.length > 100) {
                const row = tbody.insertRow();
                row.innerHTML = \`<td colspan="7" style="text-align: center; color: #666; font-style: italic;">
                    Showing first 100 of \${filteredPackets.length} packets
                </td>\`;
            }
        }

        function displayFlowDiagram() {
            const flowContainer = document.getElementById('flowDiagram');
            flowContainer.innerHTML = '';

            const flows = {};
            filteredPackets.forEach(p => {
                if (p.src && p.dst) {
                    const flowKey = \`\${p.src}:\${p.srcPort || '*'} \u2192 \${p.dst}:\${p.dstPort || '*'} (\${p.protocol})\`;
                    flows[flowKey] = (flows[flowKey] || 0) + 1;
                }
            });

            const topFlows = Object.entries(flows)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 20);

            topFlows.forEach(([flow, count]) => {
                const [src, dst, protocol] = flow.match(/([^\u2192]+)\u2192([^(]+)\\(([^)]+)\\)/).slice(1);

                const flowItem = document.createElement('div');
                flowItem.className = 'flow-item';
                flowItem.innerHTML = \`
                    <div class="flow-src">\${src.trim()}</div>
                    <div class="flow-arrow">\u2192</div>
                    <div class="flow-dst">\${dst.trim()}</div>
                    <div class="flow-info">\${protocol.trim()} \u2022 \${count} packets</div>
                \`;
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
    <\/script>
</body>
</html>
`;
export {
  index_default as default
};
//# sourceMappingURL=index.js.map