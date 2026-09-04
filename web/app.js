/* Netra dashboard front end - vanilla JS, polling based, no external assets. */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const state = {
    tab: 'live',
    newestPacket: 0,
    packets: new Map(),
    captureRunning: false,
    scanRunning: false,
    fields: [],
    timers: {},
    history: [],
  };

  // ------------------------------------------------------------ utilities
  async function api(path, params) {
    const url = new URL(path, window.location.origin);
    if (params) Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v); });
    const response = await fetch(url.toString(), { headers: { Accept: 'application/json' } });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`${response.status} ${text.slice(0, 200)}`);
    }
    return response.json();
  }

  function bytes(value) {
    if (value === undefined || value === null) return '-';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let v = Number(value), i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function number(value) {
    if (value === undefined || value === null) return '-';
    return Number(value).toLocaleString();
  }

  function rate(pps) {
    if (!pps) return '0 pps';
    return `${pps.toFixed(pps < 10 ? 2 : 0)} pps`;
  }

  function text(node, value) { if (node) node.textContent = value === undefined || value === null ? '' : String(value); }

  function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

  function el(tag, className, content) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined) node.textContent = content;
    return node;
  }

  function setChip(node, label, kind) {
    if (!node) return;
    node.textContent = label;
    node.className = 'chip' + (kind ? ' ' + kind : '');
  }

  function fillTable(table, rows) {
    if (!table) return;
    const tbody = table.tBodies[0];
    clear(tbody);
    rows.forEach((cells) => {
      const tr = document.createElement('tr');
      cells.forEach((cell) => {
        const td = document.createElement('td');
        if (cell && typeof cell === 'object') {
          if (cell.className) td.className = cell.className;
          td.textContent = cell.text === undefined ? '' : String(cell.text);
          if (cell.title) td.title = cell.title;
        } else {
          td.textContent = cell === undefined || cell === null ? '' : String(cell);
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    return tbody;
  }

  function bars(container, entries, valueFormatter) {
    if (!container) return;
    clear(container);
    const max = entries.reduce((m, e) => Math.max(m, e.value), 0) || 1;
    entries.forEach((entry) => {
      const row = el('div', 'bar-row');
      row.appendChild(el('span', 'name', entry.name));
      const track = el('div', 'track');
      const fill = el('div', 'fill');
      fill.style.width = `${Math.max(1, (entry.value / max) * 100)}%`;
      track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(el('span', 'value', valueFormatter ? valueFormatter(entry) : number(entry.value)));
      container.appendChild(row);
    });
    if (!entries.length) container.appendChild(el('div', 'muted', 'no data yet'));
  }

  // --------------------------------------------------------------- tabs
  function selectTab(name) {
    state.tab = name;
    document.querySelectorAll('.tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === name));
    document.querySelectorAll('.panel').forEach((panel) => panel.classList.toggle('active', panel.id === `panel-${name}`));
    if (name === 'stats') refreshStats();
    if (name === 'flows') refreshFlows();
    if (name === 'hosts') refreshHosts();
    if (name === 'system') refreshSystem();
    if (name === 'scan') refreshScanResult();
  }

  document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => selectTab(tab.dataset.tab)));

  // -------------------------------------------------------------- status
  async function refreshStatus() {
    let data;
    try {
      data = await api('/api/status');
    } catch (error) {
      setChip($('chipVersion'), 'server unreachable', 'error');
      return;
    }
    const server = data.server || {};
    setChip($('chipVersion'), `netra ${server.version || ''}`);
    const capture = data.capture || {};
    state.captureRunning = !!capture.running;
    setChip(
      $('chipCapture'),
      capture.running
        ? `capturing · ${number(capture.packets)} pkts`
        : `capture idle · ${number(capture.packets || 0)} pkts`,
      capture.running ? 'live' : (capture.error ? 'error' : '')
    );
    $('btnCaptureStart').disabled = capture.running;
    $('btnCaptureStop').disabled = !capture.running;

    const scan = data.scan || {};
    state.scanRunning = !!scan.running;
    setChip(
      $('chipScan'),
      scan.running ? `scanning ${Math.round(scan.percent || 0)}%` : `scan idle · ${number(scan.open_ports || 0)} open`,
      scan.running ? 'busy' : (scan.error ? 'error' : '')
    );
    $('btnScanStart').disabled = scan.running;
    $('btnScanStop').disabled = !scan.running;

    const counts = data.counts || {};
    setChip($('chipFlows'), `${number(counts.flows || 0)} flows`);
    text($('liveCounters'), `${number(capture.packets)} packets · ${bytes(capture.bytes)}${capture.filter ? ` · filter: ${capture.filter}` : ''}`);
    text($('liveRate'), `${rate(capture.packets_per_second)} · ${capture.backend || capture.source || 'no source'}`);
    text($('footerInfo'), `Netra ${server.version || ''} · ${server.assets || ''} · ${server.storage || ''}`);

    if (capture.error) text($('liveHint'), `capture error: ${capture.error}`);
    else if (capture.warnings && capture.warnings.length) text($('liveHint'), capture.warnings.join(' · '));
    else if (!capture.running && !capture.packets) {
      text($('liveHint'), 'Pick an interface and start a capture, or press “Demo traffic” to analyse generated packets without privileges.');
    }

    if (state.tab === 'scan' && scan.running) refreshScanStatus(scan);
  }

  // -------------------------------------------------------- live packets
  async function refreshPackets() {
    if (state.tab !== 'live') return;
    let data;
    try {
      data = await api('/api/packets', { since: state.newestPacket, limit: 400 });
    } catch (error) {
      return;
    }
    const tbody = $('packetTable').tBodies[0];
    (data.packets || []).forEach((packet) => {
      state.packets.set(packet.number, packet);
      if (packet.number > state.newestPacket) state.newestPacket = packet.number;
      const tr = document.createElement('tr');
      tr.dataset.number = packet.number;
      if (packet.malformed) tr.className = 'bad';
      tr.appendChild(el('td', 'num', packet.number));
      tr.appendChild(el('td', 'mono', (packet.time || '').split(' ')[1] || packet.time));
      tr.appendChild(el('td', 'mono', packet.source + (packet.src_port ? `:${packet.src_port}` : '')));
      tr.appendChild(el('td', 'mono', packet.destination + (packet.dst_port ? `:${packet.dst_port}` : '')));
      tr.appendChild(el('td', `proto-${packet.protocol || ''}`, packet.protocol || '-'));
      tr.appendChild(el('td', 'num', packet.length));
      tr.appendChild(el('td', '', packet.info || ''));
      tr.addEventListener('click', () => showPacketDetail(packet.number, tr));
      tbody.appendChild(tr);
    });

    const autoscroll = $('autoscroll').checked;
    const maxRows = 1200;
    while (tbody.rows.length > maxRows) {
      const removed = tbody.rows[0];
      state.packets.delete(Number(removed.dataset.number));
      tbody.removeChild(removed);
    }
    if (autoscroll && tbody.rows.length) {
      const wrap = tbody.parentElement.parentElement;
      wrap.scrollTop = wrap.scrollHeight;
    }
    if (data.dropped) {
      text($('liveHint'), `${number(data.dropped)} packet(s) rotated out of the ring buffer - increase the ring size or use a display filter.`);
    }
  }

  async function showPacketDetail(packetNumber, row) {
    document.querySelectorAll('#packetTable tbody tr.selected').forEach((tr) => tr.classList.remove('selected'));
    if (row) row.classList.add('selected');
    const detail = $('packetDetail');
    detail.textContent = 'loading…';
    try {
      const data = await api('/api/packet', { number: packetNumber });
      const packet = data.packet || {};
      const lines = [];
      lines.push(`#${packet.number}  ${packet.time || ''}  ${packet.length || 0} bytes  ${packet.protocol || ''}`);
      lines.push(`${packet.source || packet.src || ''} → ${packet.destination || packet.dst || ''}`);
      if (packet.layers || packet.protocols) lines.push(`layers: ${packet.layers || packet.protocols}`);
      if (packet.info) lines.push(`info:   ${packet.info}`);
      if (packet.malformed) lines.push(`MALFORMED: ${packet.malformed_reason || ''}`);

      if (Array.isArray(data.detail) && data.detail.length) {
        lines.push('');
        lines.push(...data.detail);
      } else {
        ['ethernet', 'ip', 'ipv6', 'tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'tls', 'dhcp', 'ntp'].forEach((name) => {
          const section = packet[name];
          if (!section) return;
          lines.push('');
          lines.push(`[${name}]`);
          Object.entries(section).forEach(([key, value]) => {
            if (value === null || value === undefined || value === '') return;
            if (Array.isArray(value)) {
              lines.push(`  ${key}: ${value.map((v) => (typeof v === 'object' ? JSON.stringify(v) : v)).join(', ')}`);
            } else if (typeof value === 'object') {
              lines.push(`  ${key}: ${JSON.stringify(value)}`);
            } else {
              lines.push(`  ${key}: ${value}`);
            }
          });
        });
      }
      if (packet.hex) {
        lines.push('');
        lines.push('[hex]');
        lines.push(packet.hex);
      }
      detail.textContent = lines.join('\n');
    } catch (error) {
      detail.textContent = `cannot load packet ${packetNumber}: ${error.message}`;
    }
  }

  async function startCapture(demo) {
    const params = demo
      ? { demo: 'mixed', seconds: $('captureSeconds').value || 20, filter: $('captureFilter').value }
      : {
          interface: $('captureInterface').value,
          filter: $('captureFilter').value,
          count: $('captureCount').value || 0,
          seconds: $('captureSeconds').value || 0,
        };
    try {
      const result = await api('/api/capture/start', params);
      if (result.error) throw new Error(result.error);
      state.newestPacket = 0;
      clear($('packetTable').tBodies[0]);
      state.packets.clear();
      text($('liveHint'), demo ? 'generating demo traffic…' : 'capture started');
      $('packetDetail').textContent = 'Select a packet to inspect its decoded layers.';
    } catch (error) {
      text($('liveHint'), `cannot start capture: ${error.message}`);
    }
    refreshStatus();
  }

  async function stopCapture() {
    try { await api('/api/capture/stop'); } catch (error) { text($('liveHint'), error.message); }
    refreshStatus();
  }

  // -------------------------------------------------------------- stats
  async function refreshStats() {
    let data;
    try {
      data = await api('/api/stats');
    } catch (error) {
      return;
    }
    const capture = data.capture || {};
    const cards = [
      { label: 'Packets', value: number(data.packets || capture.packets), sub: `${number(capture.matched || 0)} matched` },
      { label: 'Bytes', value: bytes(data.bytes), sub: `${bytes(data.payload_bytes)} payload` },
      { label: 'Rate', value: rate(capture.packets_per_second), sub: `${bytes((data.bits_per_second || 0) / 8)}/s` },
      { label: 'Duration', value: `${(capture.duration_seconds || 0).toFixed(1)} s`, sub: data.first_packet ? `since ${data.first_packet}` : '' },
      { label: 'Avg packet', value: `${(data.average_packet_size || 0).toFixed(0)} B`, sub: `min ${data.smallest_packet || 0} / max ${data.largest_packet || 0}` },
      { label: 'Flows', value: number(data.flows || 0), sub: `${number((data.layers || {}).tcp || 0)} TCP · ${number((data.layers || {}).udp || 0)} UDP` },
      { label: 'Endpoints', value: number((data.top_talkers || []).length), sub: `${number((data.top_conversations || []).length)} conversations` },
      { label: 'Anomalies', value: number(((data.issues || {}).malformed || 0) + ((data.issues || {}).bad_checksums || 0) + ((data.issues || {}).retransmissions || 0)), sub: `${number((data.issues || {}).retransmissions || 0)} retransmissions` },
    ];
    const container = $('statCards');
    clear(container);
    cards.forEach((card) => {
      const node = el('div', 'stat');
      node.appendChild(el('div', 'label', card.label));
      node.appendChild(el('div', 'value', card.value));
      node.appendChild(el('div', 'sub', card.sub || ''));
      container.appendChild(node);
    });

    bars($('protocolBars'), (data.protocols || []).slice(0, 14).map((p) => ({
      name: p.protocol, value: Number(p.packets || 0), extra: p,
    })), (entry) => `${number(entry.value)} (${entry.extra.packet_percent.toFixed(1)}%)`);

    const series = (data.time_series || []).slice(-60);
    state.history = series;
    const chart = $('throughputChart');
    clear(chart);
    const maxBits = series.reduce((m, s) => Math.max(m, Number(s.bits_per_second || 0)), 0) || 1;
    series.forEach((point) => {
      const bar = el('div');
      bar.style.height = `${Math.max(2, (Number(point.bits_per_second || 0) / maxBits) * 100)}%`;
      bar.dataset.label = `${new Date(Number(point.time_ms)).toLocaleTimeString()} · ${bytes(point.bytes)} · ${(point.bits_per_second / 1e6).toFixed(2)} Mbps`;
      chart.appendChild(bar);
    });
    if (!series.length) chart.appendChild(el('div', 'muted', 'waiting for packets…'));

    bars($('packetSizes'), (data.packet_sizes || []).map((s) => ({ name: `${s.range} B`, value: Number(s.packets || 0) })));

    fillTable($('talkerTable'), (data.top_talkers || []).map((t) => [
      { text: t.address, className: 'mono' },
      { text: number(t.tx_packets), className: 'num' },
      { text: bytes(t.tx_bytes), className: 'num' },
      { text: number(t.rx_packets), className: 'num' },
      { text: bytes(t.rx_bytes), className: 'num' },
    ]));

    fillTable($('conversationTable'), (data.top_conversations || []).map((c) => [
      { text: `${c.a}:${c.port_a} ↔ ${c.b}:${c.port_b}`, className: 'mono' },
      { text: number(c.packets), className: 'num' },
      { text: bytes(c.bytes), className: 'num' },
      c.application || c.protocol || '',
    ]));

    const issues = data.issues || {};
    const layers = data.layers || {};
    const app = data.application || {};
    const notes = [
      ['Source', `${capture.source || '-'} (${capture.backend || '-'})`],
      ['Display filter', capture.filter || '(none)'],
      ['Dropped by kernel', number(capture.dropped || 0)],
      ['Layers', `IPv4 ${number(layers.ipv4)} · IPv6 ${number(layers.ipv6)} · ARP ${number(layers.arp)} · TCP ${number(layers.tcp)} · UDP ${number(layers.udp)} · ICMP ${number(layers.icmp)}`],
      ['Application', `DNS ${number(app.dns)} · HTTP ${number(app.http)} · TLS ${number(app.tls)} · DHCP ${number(app.dhcp)} · NTP ${number(app.ntp)}`],
      ['TCP flags', `SYN ${number((data.tcp_flags || {}).syn)} · SYN/ACK ${number((data.tcp_flags || {}).syn_ack)} · FIN ${number((data.tcp_flags || {}).fin)} · RST ${number((data.tcp_flags || {}).rst)}`],
      ['Malformed', number(issues.malformed || 0)],
      ['Bad checksums', number(issues.bad_checksums || 0)],
      ['Fragments', number(issues.fragments || 0)],
      ['Retransmissions', number(issues.retransmissions || 0)],
    ];
    const notesNode = $('statsNotes');
    clear(notesNode);
    notes.forEach(([label, value]) => {
      const row = el('div');
      row.appendChild(el('span', '', label));
      row.appendChild(el('span', '', value));
      notesNode.appendChild(row);
    });
  }

  // -------------------------------------------------------------- flows
  const flowSortMap = { last: 'last', bytes: 'bytes', packets: 'packets', duration: 'duration' };

  async function refreshFlows() {
    let data;
    try {
      data = await api('/api/flows', { limit: $('flowLimit').value || 100, sort: flowSortMap[$('flowSort').value] });
    } catch (error) {
      return;
    }
    const summary = data.summary || {};
    text($('flowSummary'), `${number(summary.sessions || 0)} sessions · ${number(summary.packets || 0)} packets · ${bytes(summary.bytes || 0)} · ${number(summary.retransmissions || 0)} retransmissions`);
    fillTable($('flowTable'), (data.sessions || []).map((session) => [
      session.protocol || '',
      { text: `${session.source}${session.source_port ? ':' + session.source_port : ''}`, className: 'mono' },
      { text: `${session.destination}${session.destination_port ? ':' + session.destination_port : ''}`, className: 'mono' },
      { text: number(session.packets), className: 'num' },
      { text: bytes(session.bytes), className: 'num' },
      { text: session.state, className: `state-${session.state}` },
      session.application || session.service || '',
      { text: session.info || '', title: session.info || '' },
    ]));
  }

  // --------------------------------------------------------------- scan
  async function startScan() {
    const params = {
      targets: $('scanTargets').value,
      ports: $('scanPorts').value || 'top100',
      types: $('scanType').value,
      timing: $('scanTiming').value,
      version: $('scanType').value.includes('version') ? 'true' : 'false',
    };
    text($('scanError'), '');
    try {
      const result = await api('/api/scan/start', params);
      if (result.error) throw new Error(result.error);
      text($('scanPhase'), 'starting…');
    } catch (error) {
      text($('scanError'), `cannot start scan: ${error.message}`);
    }
    refreshStatus();
  }

  async function stopScan() {
    try { await api('/api/scan/stop'); } catch (error) { text($('scanError'), error.message); }
    refreshStatus();
  }

  function refreshScanStatus(scan) {
    $('scanProgressBar').style.width = `${Math.min(100, scan.percent || 0)}%`;
    text($('scanPhase'), `${scan.phase || 'running'}${scan.current_host ? ` · ${scan.current_host}` : ''} · ${Math.round(scan.percent || 0)}%`);
    text($('scanCounters'), `${number(scan.probes_done || 0)}/${number(scan.probes_total || 0)} probes · ${number(scan.hosts_up || 0)}/${number(scan.hosts_total || 0)} hosts up · ${number(scan.open_ports || 0)} open ports · ${(scan.elapsed_seconds || 0).toFixed(1)}s`);
  }

  async function refreshScanResult() {
    let data;
    try {
      data = await api('/api/scan/result');
    } catch (error) {
      return;
    }
    if (data.progress) refreshScanStatus(data.progress);
    if (data.progress && data.progress.error) text($('scanError'), data.progress.error);
    const hosts = data.hosts || [];
    fillTable($('scanTable'), hosts.map((host) => {
      const open = (host.ports || []).filter((p) => p.state === 'open');
      return [
        { text: host.address, className: 'mono' },
        host.hostname || '',
        { text: host.up ? 'up' : 'down', className: host.up ? 'state-open' : 'state-closed' },
        { text: host.up ? `${(host.latency_ms || 0).toFixed(2)} ms` : '-', className: 'num' },
        { text: open.map((p) => `${p.port}/${p.protocol}`).join(', ') || (host.up ? 'none' : '-'), className: 'mono' },
        open.length ? open.map((p) => `${p.port} ${p.service || ''}${p.product ? ' ' + p.product : ''}${p.version ? ' ' + p.version : ''}`).join(' · ') : (host.os_guess || host.mac || ''),
      ];
    }));
  }

  // -------------------------------------------------------------- hosts
  async function refreshHosts() {
    let data;
    try {
      data = await api('/api/hosts');
    } catch (error) {
      return;
    }
    fillTable($('neighborTable'), (data.neighbors || []).map((n) => [
      { text: n.address, className: 'mono' },
      { text: n.mac || '-', className: 'mono' },
      n.interface || n.interface_name || '',
      n.state || '',
      n.hostname || '',
    ]));
    fillTable($('observedTable'), (data.observed_hosts || []).map((h) => [
      { text: h.address, className: 'mono' },
      { text: h.mac || '-', className: 'mono' },
      { text: number(h.tx_packets), className: 'num' },
      { text: number(h.rx_packets), className: 'num' },
      { text: bytes(Number(h.tx_bytes || 0) + Number(h.rx_bytes || 0)), className: 'num' },
    ]));
    fillTable($('scannedTable'), (data.scanned_hosts || []).map((h) => [
      { text: h.address, className: 'mono' },
      h.hostname || '',
      { text: h.up ? 'up' : 'down', className: h.up ? 'state-open' : 'state-closed' },
      { text: number(h.ports_open || 0), className: 'num' },
      { text: (h.ports || []).filter((p) => p.state === 'open').map((p) => `${p.port}/${p.protocol}`).join(', '), className: 'mono' },
    ]));
  }

  // ------------------------------------------------------------- system
  async function refreshSystem() {
    try {
      const [interfaces, capabilities, fields] = await Promise.all([
        api('/api/interfaces'),
        api('/api/capabilities'),
        state.fields.length ? Promise.resolve({ fields: state.fields }) : api('/api/filters'),
      ]);

      fillTable($('interfaceTable'), (interfaces.interfaces || []).map((i) => [
        { text: i.name, className: 'mono' },
        i.up ? (i.running ? 'up/running' : 'up') : 'down',
        { text: i.mac || '-', className: 'mono' },
        { text: i.addresses || i.address_summary || '-', className: 'mono' },
        { text: i.mtu || '-', className: 'num' },
        i.driver || '',
      ]));
      fillTable($('routeTable'), (interfaces.routes || []).map((r) => [
        { text: r.destination || (r.default ? 'default' : '-'), className: 'mono' },
        { text: r.gateway || '-', className: 'mono' },
        r.interface || r.interface_name || '',
        { text: r.metric || 0, className: 'num' },
      ]));

      const deps = capabilities.dependencies || {};
      const notes = [
        ['Version', `${capabilities.version} (${capabilities.build_type})`],
        ['Commit', capabilities.git_commit || '-'],
        ['Built', capabilities.build_date || '-'],
        ['Compiler', capabilities.compiler || '-'],
        ['System', `${capabilities.system || '-'} · ${capabilities.cpus || '?'} CPU(s)`],
        ['Raw sockets', capabilities.raw_sockets ? 'available' : `not permitted — ${capabilities.raw_socket_advice || 'run with sudo or setcap'}`],
        ['libpcap / Npcap', deps.libpcap ? 'compiled in' : 'not found (built-in AF_PACKET capture used)'],
        ['PcapPlusPlus', deps.pcapplusplus ? 'compiled in' : 'not found'],
        ['Boost.Asio', deps.boost_asio ? 'compiled in' : `not found — ${capabilities.asio || 'poll() prober used'}`],
        ['OpenSSL', deps.openssl ? 'compiled in' : 'not found (built-in TLS/X.509 parser used)'],
        ['SQLite', deps.sqlite ? 'compiled in' : 'not found'],
        ['Storage', capabilities.storage || '-'],
        ['Web assets', capabilities.assets || '-'],
        ['Capture backends', (capabilities.capture_backends || []).map((b) => `${b.id}${b.usable ? '' : ' (unusable)'}`).join(', ')],
      ];
      const list = $('capabilityList');
      clear(list);
      notes.forEach(([label, value]) => {
        const row = el('div');
        row.appendChild(el('span', '', label));
        row.appendChild(el('span', '', value));
        list.appendChild(row);
      });

      state.fields = fields.fields || [];
      renderFields('');
    } catch (error) {
      text($('capabilityList'), `cannot load system information: ${error.message}`);
    }
  }

  function renderFields(query) {
    const needle = (query || '').toLowerCase();
    const rows = state.fields
      .filter((f) => !needle || f.name.toLowerCase().includes(needle) || (f.description || '').toLowerCase().includes(needle))
      .slice(0, 300)
      .map((f) => [{ text: f.name, className: 'mono' }, f.type || '', f.description || '', { text: f.example || '', className: 'mono' }]);
    fillTable($('fieldTable'), rows);
  }

  // -------------------------------------------------------- interface list
  async function loadInterfaces() {
    try {
      const data = await api('/api/interfaces');
      const select = $('captureInterface');
      clear(select);
      (data.interfaces || []).forEach((i) => {
        if (!i.up) return;
        const option = document.createElement('option');
        option.value = i.name;
        option.textContent = `${i.name}${i.address_summary ? ' · ' + i.address_summary : ''}`;
        select.appendChild(option);
      });
      if (!select.options.length) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'no interfaces available';
        select.appendChild(option);
      }
    } catch (error) {
      /* ignore - the select stays empty */
    }
  }

  // -------------------------------------------------------------- wiring
  $('btnCaptureStart').addEventListener('click', () => startCapture(false));
  $('btnCaptureStop').addEventListener('click', stopCapture);
  $('btnDemo').addEventListener('click', () => startCapture(true));
  $('btnClearPackets').addEventListener('click', () => {
    clear($('packetTable').tBodies[0]);
    state.packets.clear();
    state.newestPacket = 0;
    $('packetDetail').textContent = 'View cleared - polling continues from the newest packet.';
  });
  $('btnScanStart').addEventListener('click', startScan);
  $('btnScanStop').addEventListener('click', stopScan);
  $('btnFlowsRefresh').addEventListener('click', refreshFlows);
  $('btnHostsRefresh').addEventListener('click', refreshHosts);
  $('fieldSearch').addEventListener('input', (event) => renderFields(event.target.value));
  $('captureFilter').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') startCapture(false);
  });
  $('scanTargets').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') startScan();
  });

  // ------------------------------------------------------------- looping
  function loop(name, fn, intervalMs) {
    state.timers[name] = setInterval(() => { fn().catch(() => {}); }, intervalMs);
  }

  loadInterfaces();
  refreshStatus().then(() => {
    loop('status', refreshStatus, 1000);
    loop('packets', refreshPackets, 700);
    loop('stats', () => (state.tab === 'stats' ? refreshStats() : Promise.resolve()), 2000);
    loop('flows', () => (state.tab === 'flows' ? refreshFlows() : Promise.resolve()), 2500);
    loop('scan', () => (state.tab === 'scan' ? refreshScanResult() : Promise.resolve()), 2000);
    loop('hosts', () => (state.tab === 'hosts' ? refreshHosts() : Promise.resolve()), 5000);
  });
})();
