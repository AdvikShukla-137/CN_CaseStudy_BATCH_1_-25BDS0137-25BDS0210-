import struct, sys, os, re, json, argparse, socket
from collections import Counter, defaultdict
import numpy as np, pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def read_pcapng(path):
    data = open(path, 'rb').read()
    off = 0
    end = '<'
    ifaces = []
    pkts = []
    while off + 12 <= len(data):
        btype = struct.unpack_from('<I', data, off)[0]
        if btype == 168627466:
            bom = struct.unpack_from('<I', data, off + 8)[0]
            end = '<' if bom == 439041101 else '>'
        btype, blen = struct.unpack_from(end + 'II', data, off)
        body = data[off + 8:off + blen - 4]
        if btype == 1:
            link = struct.unpack_from(end + 'H', body, 0)[0]
            res = 1e-06
            p = 8
            while p + 4 <= len(body):
                code, ln = struct.unpack_from(end + 'HH', body, p)
                if code == 0:
                    break
                if code == 9:
                    v = body[p + 4]
                    res = 2.0 ** (-(v & 127)) if v & 128 else 10.0 ** (-v)
                p += 4 + (ln + 3 & ~3)
            ifaces.append((link, res))
        elif btype == 6:
            iid, th, tl, cap, orig = struct.unpack_from(end + 'IIIII', body, 0)
            ts = (th << 32 | tl) * ifaces[iid][1]
            pkts.append((ts, orig, body[20:20 + cap], ifaces[iid][0]))
        off += blen
    return pkts

def ipstr(b):
    return socket.inet_ntoa(b)

def ip6str(b):
    return socket.inet_ntop(socket.AF_INET6, b)

def dissect(ts, orig, raw, link):
    r = dict(time_epoch=ts, length=orig, src='', dst='', protocol='Other', sport=None, dport=None, ttl=None, icmp_type=None, icmp_id=None, icmp_seq=None, tcp_flags=None, tcp_seq=None, tcp_ack=None, payload=0, ip_len=None, ip_csum_ok=None, icmp_csum_ok=None)
    if link != 1 or len(raw) < 14:
        return r
    et = struct.unpack_from('!H', raw, 12)[0]
    o = 14
    while et in (33024, 34984) and len(raw) >= o + 4:
        et = struct.unpack_from('!H', raw, o + 2)[0]
        o += 4
    if et == 2054:
        r['protocol'] = 'ARP'
        if len(raw) >= o + 28:
            r['src'] = ipstr(raw[o + 14:o + 18])
            r['dst'] = ipstr(raw[o + 24:o + 28])
        return r
    if et == 2048 and len(raw) >= o + 20:
        ihl = (raw[o] & 15) * 4
        proto = raw[o + 9]
        r['ttl'] = raw[o + 8]
        r['ip_len'] = struct.unpack_from('!H', raw, o + 2)[0]
        r['src'] = ipstr(raw[o + 12:o + 16])
        r['dst'] = ipstr(raw[o + 16:o + 20])
        h = raw[o:o + ihl]
        s = sum(struct.unpack('!%dH' % (len(h) // 2), h))
        while s >> 16:
            s = (s & 65535) + (s >> 16)
        r['ip_csum_ok'] = s == 65535
        t = o + ihl
        tl = max(0, r['ip_len'] - ihl)
    elif et == 34525 and len(raw) >= o + 40:
        proto = raw[o + 6]
        r['ttl'] = raw[o + 7]
        r['src'] = ip6str(raw[o + 8:o + 24])
        r['dst'] = ip6str(raw[o + 24:o + 40])
        t = o + 40
        tl = struct.unpack_from('!H', raw, o + 4)[0]
        while proto in (0, 43, 60) and len(raw) >= t + 8:
            proto = raw[t]
            step = (raw[t + 1] + 1) * 8
            t += step
            tl -= step
    else:
        return r
    if proto == 1 and len(raw) >= t + 8:
        r['protocol'] = 'ICMP'
        ty, cd = (raw[t], raw[t + 1])
        r['icmp_type'] = ty
        if ty in (0, 8):
            r['icmp_id'], r['icmp_seq'] = struct.unpack_from('!HH', raw, t + 4)
        m = raw[t:t + tl]
        if len(m) % 2:
            m += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(m) // 2), m))
        while s >> 16:
            s = (s & 65535) + (s >> 16)
        r['icmp_csum_ok'] = s == 65535
        r['payload'] = max(0, tl - 8)
    elif proto == 58:
        r['protocol'] = 'ICMPv6'
        r['icmp_type'] = raw[t] if len(raw) > t else None
    elif proto == 2:
        r['protocol'] = 'IGMP'
    elif proto == 6 and len(raw) >= t + 20:
        r['protocol'] = 'TCP'
        sp, dp, sq, ak = struct.unpack_from('!HHII', raw, t)
        doff = (raw[t + 12] >> 4) * 4
        r.update(sport=sp, dport=dp, tcp_seq=sq, tcp_ack=ak, tcp_flags=raw[t + 13], payload=max(0, tl - doff))
    elif proto == 17 and len(raw) >= t + 8:
        r['protocol'] = 'UDP'
        sp, dp = struct.unpack_from('!HH', raw, t)
        r.update(sport=sp, dport=dp, payload=max(0, tl - 8))
    return r

def app_hint(r):
    ports = {r['sport'], r['dport']}
    if r['protocol'] == 'UDP':
        if 443 in ports:
            return 'QUIC (UDP/443)'
        if 53 in ports:
            return 'DNS'
        if 5353 in ports:
            return 'mDNS'
        if 1900 in ports:
            return 'SSDP'
    if r['protocol'] == 'TCP':
        if 443 in ports:
            return 'TLS/HTTPS (TCP/443)'
        if 80 in ports:
            return 'HTTP'
        if 53 in ports:
            return 'DNS'
    return r['protocol']

def parse_ping_log(p):
    rt = []
    summ = {}
    for ln in open(p, errors='ignore'):
        m = re.search('time[=<](\\d+)ms', ln)
        if m and 'Reply from' in ln:
            rt.append(int(m.group(1)))
        elif 'Request timed out' in ln or 'unreachable' in ln:
            rt.append(np.nan)
        m = re.search('Sent = (\\d+), Received = (\\d+), Lost = (\\d+)', ln)
        if m:
            summ.update(sent=int(m.group(1)), received=int(m.group(2)), lost=int(m.group(3)))
        m = re.search('Minimum = (\\d+)ms, Maximum = (\\d+)ms, Average = (\\d+)ms', ln)
        if m:
            summ.update(min=int(m.group(1)), max=int(m.group(2)), avg=int(m.group(3)))
    return (np.array(rt, float), summ)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pcap')
    ap.add_argument('root')
    ap.add_argument('--wireshark-csv')
    ap.add_argument('--ping-log')
    a = ap.parse_args()
    D = os.path.join(a.root, 'data')
    G = os.path.join(a.root, 'graphs')
    os.makedirs(D, exist_ok=True)
    os.makedirs(G, exist_ok=True)
    raw = read_pcapng(a.pcap)
    rows = []
    for i, (ts, orig, b, link) in enumerate(raw, 1):
        r = dissect(ts, orig, b, link)
        r['no'] = i
        r['app'] = app_hint(r)
        rows.append(r)
    df = pd.DataFrame(rows)
    t0 = df.time_epoch.iloc[0]
    df['rel_time'] = df.time_epoch - t0
    df.to_csv(os.path.join(D, 'AllPackets.csv'), index=False, float_format='%.9f')
    R = {}
    span = df.time_epoch.iloc[-1] - t0
    N = len(df)
    TB = int(df.length.sum())
    R['capture'] = dict(packets=N, bytes=TB, start_utc=pd.to_datetime(t0, unit='s').strftime('%Y-%m-%d %H:%M:%S'), end_utc=pd.to_datetime(df.time_epoch.iloc[-1], unit='s').strftime('%Y-%m-%d %H:%M:%S'), span_s=span, avg_len=TB / N, median_len=float(df.length.median()), min_len=int(df.length.min()), max_len=int(df.length.max()), pps=N / span, Bps=TB / span, bps=8 * TB / span)
    pc = df.groupby('protocol').agg(packets=('no', 'count'), bytes=('length', 'sum')).sort_values('packets', ascending=False)
    pc['pct_packets'] = 100 * pc.packets / N
    pc['pct_bytes'] = 100 * pc.bytes / TB
    R['protocols'] = pc.reset_index().to_dict('records')
    R['app_hints'] = df.app.value_counts().to_dict()
    ic = df[df.protocol == 'ICMP']
    req = ic[ic.icmp_type == 8].copy()
    rep = ic[ic.icmp_type == 0].copy()
    pairs = []
    pend = {}
    for _, x in ic.iterrows():
        k = (x.icmp_id, x.icmp_seq)
        if x.icmp_type == 8:
            pend.setdefault(k, []).append(x)
        elif x.icmp_type == 0 and pend.get(k):
            q = pend[k].pop(0)
            pairs.append(dict(seq=int(q.icmp_seq), req_no=int(q.no), rep_no=int(x.no), req_time=q.rel_time, interval_ms=(x.time_epoch - q.time_epoch) * 1000.0, req_ttl=int(q.ttl), rep_ttl=int(x.ttl), length=int(q.length), src=q.src, dst=q.dst))
    pr = pd.DataFrame(pairs)
    orphans = len(rep) - len(pr)
    rtt, psum = parse_ping_log(a.ping_log)
    pr['ping_log_rtt_ms'] = rtt[:len(pr)] if len(rtt) >= len(pr) else np.nan
    pr.to_csv(os.path.join(D, 'Cleaned.csv'), index=False, float_format='%.6f')
    pd.DataFrame(dict(index=range(1, len(rtt) + 1), rtt_ms=rtt)).to_csv(os.path.join(D, 'ping_log_rtt.csv'), index=False)
    chk = {}
    if a.wireshark_csv:
        w = pd.read_csv(a.wireshark_csv)
        chk['rows'] = len(w)
        m = w.merge(df, left_on='No.', right_on='no', suffixes=('_w', '_p'))
        chk['matched_rows'] = len(m)
        chk['src_dst_len_ttl_seq_match'] = bool(((m.Source == m.src) & (m.Destination == m.dst) & (m.Length == m.length)).all())
        chk['ttl_match'] = bool((m['Time to Live'] == m.ttl).all())
        chk['seq_match'] = bool((m['Sequence Number (BE)'] == m.icmp_seq).all())
        chk['max_time_diff_s'] = float((m['Epoch Arrival Time'] - m.time_epoch).abs().max())
        rin = w.Info.str.extract('reply in (\\d+)')[0].dropna().astype(int)
        rq = w[w.Info.str.contains('reply in')]['No.'].astype(int)
        mp = dict(zip(pr.req_no, pr.rep_no))
        chk['wireshark_reply_links_agree'] = int(sum((mp.get(q) == r for q, r in zip(rq, rin))))
    R['crosscheck'] = chk
    iv = pr.interval_ms
    R['icmp'] = dict(packets=len(ic), requests=len(req), replies=len(rep), pairs=len(pr), orphans=int(orphans), duplicates=int(req.duplicated(['icmp_id', 'icmp_seq']).sum()), bytes=int(ic.length.sum()), pct_pkts=100 * len(ic) / N, pct_bytes=100 * ic.length.sum() / TB, frame_sizes=sorted(ic.length.unique().tolist()), span_s=float(ic.time_epoch.iloc[-1] - ic.time_epoch.iloc[0]), req_ttl=Counter(pr.req_ttl).most_common(), rep_ttl=Counter(pr.rep_ttl).most_common(), payload=int(req.payload.iloc[0]), icmp_csum_fail=int((ic.icmp_csum_ok == False).sum()), ip_csum_bad_req=int(((ic.ip_csum_ok == False) & (ic.icmp_type == 8)).sum()), ip_csum_bad_rep=int(((ic.ip_csum_ok == False) & (ic.icmp_type == 0)).sum()))
    R['icmp']['pps'] = len(ic) / R['icmp']['span_s']
    R['icmp']['Bps'] = R['icmp']['bytes'] / R['icmp']['span_s']
    R['icmp']['bps'] = 8 * R['icmp']['Bps']
    R['icmp']['avg_len'] = float(ic.length.mean())
    R['turnaround_ms'] = dict(mean=iv.mean(), median=iv.median(), min=iv.min(), max=iv.max(), std=iv.std())
    gaps = np.diff(pr.req_time.values)
    R['req_spacing_s'] = dict(mean=gaps.mean(), std=gaps.std(), min=gaps.min(), max=gaps.max())
    order = np.argsort(-gaps)[:4]
    R['longest_gaps'] = [dict(seq=int(pr.seq[i + 1]), gap_s=float(gaps[i]), t_s=float(pr.req_time[i + 1]), ping_ms=float(rtt[i + 1]) if i + 1 < len(rtt) else None) for i in order]
    lossr = dict(sent_log=psum.get('sent'), recv_log=psum.get('received'), lost_log=psum.get('lost'), requests_cap=len(req), replies_cap=len(rep), timeouts_in_log=int(np.isnan(rtt).sum()))
    R['loss'] = lossr
    R['ping_summary'] = psum
    v = rtt[~np.isnan(rtt)]
    med = float(np.median(v))
    dif = np.abs(np.diff(v))
    R['rtt'] = dict(n=len(v), median=med, mean=v.mean(), min=v.min(), max=v.max(), std=v.std(ddof=1), p95=np.percentile(v, 95), p99=np.percentile(v, 99), mean_abs_diff=dif.mean(), max_abs_diff=dif.max(), n_3to6=int(((v >= 3) & (v <= 6)).sum()), pct_3to6=100 * ((v >= 3) & (v <= 6)).mean(), n_gt_3x=int((v > 3 * med).sum()), pct_gt_3x=100 * (v > 3 * med).mean(), thr_3x=3 * med)
    top = pr.assign(rtt=rtt[:len(pr)]).nlargest(8, 'rtt')[['seq', 'req_time', 'rtt']]
    R['rtt_top'] = top.to_dict('records')
    tt = pr.req_time.values
    blocks = []
    for b0 in range(0, 1800, 300):
        sel = (tt >= b0) & (tt < b0 + 300)
        vv = rtt[:len(pr)][sel]
        blocks.append(dict(block=f'{b0}-{b0 + 300}', n=int(sel.sum()), slow=int((vv > 3 * med).sum()), mean=float(np.nanmean(vv)), max=float(np.nanmax(vv))))
    R['rtt_blocks'] = blocks
    df['bin10'] = (df.rel_time // 10).astype(int)
    c10 = df.groupby('bin10').size()
    i10 = df[df.protocol == 'ICMP'].groupby('bin10').size().reindex(c10.index, fill_value=0)
    R['bins10'] = dict(median=float(c10.median()), peak=int(c10.max()), peak_t=int(c10.idxmax() * 10), icmp_min=int(i10.min()), icmp_max=int(i10.max()))
    ep = df[df.src != ''].groupby(['src', 'dst']).agg(packets=('no', 'count'), bytes=('length', 'sum')).sort_values('packets', ascending=False).head(10)
    R['top_pairs'] = ep.reset_index().to_dict('records')
    R['src_counts'] = df[df.src != ''].src.value_counts().head(5).to_dict()
    tcp = df[df.protocol == 'TCP'].copy()
    rst = tcp[tcp.tcp_flags.fillna(0).astype(int) & 4 > 0]
    flowkey = lambda x: tuple(sorted([(x.src, x.sport), (x.dst, x.dport)]))
    tcp['fk'] = tcp.apply(flowkey, axis=1)
    rst_flows = rst.apply(flowkey, axis=1).nunique()
    seen = set()
    retr = []
    for _, x in tcp.iterrows():
        if x.payload > 0 or int(x.tcp_flags) & 3:
            k = (x.src, x.sport, x.dst, x.dport, x.tcp_seq, x.payload)
            if k in seen:
                retr.append(x)
            seen.add(k)
    rdf = pd.DataFrame(retr)
    top_r = Counter(zip(rdf.dst, rdf.dport)).most_common(3) if len(rdf) else []
    R['tcp'] = dict(packets=len(tcp), rst=len(rst), rst_flows=int(rst_flows), rst_ports=Counter(np.minimum(rst.sport, rst.dport).astype(int)).most_common(4), retrans=len(rdf), retrans_pct=100 * len(rdf) / max(1, len(tcp)), retrans_top=[[f'{d}:{int(p)}', n] for (d, p), n in top_r])
    fl = df[df.src != ''].copy()
    fl['fk'] = fl.apply(lambda x: (x.protocol, x.src, int(x.sport) if pd.notna(x.sport) else '', x.dst, int(x.dport) if pd.notna(x.dport) else ''), axis=1)
    g = fl.groupby('fk').agg(packets=('no', 'count'), bytes=('length', 'sum'), t0=('rel_time', 'min'), t1=('rel_time', 'max')).reset_index()
    g['duration_s'] = g.t1 - g.t0
    g['avg_pkt_size'] = g.bytes / g.packets
    g['pkts_per_s'] = g.packets / g.duration_s.replace(0, np.nan)
    g['bytes_per_s'] = g.bytes / g.duration_s.replace(0, np.nan)
    g[['protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port']] = pd.DataFrame(g.fk.tolist(), index=g.index)
    g = g.sort_values('packets', ascending=False)[['protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 't0', 'duration_s', 'packets', 'bytes', 'avg_pkt_size', 'pkts_per_s', 'bytes_per_s']].rename(columns={'t0': 'start_s'})
    g.to_csv(os.path.join(D, 'FlowLevel.csv'), index=False, float_format='%.6f')
    R['flows'] = dict(n=len(g), icmp_flows=int((g.protocol == 'ICMP').sum()), top=g.head(5).astype(str).to_dict('records'))
    json.dump(R, open(os.path.join(D, 'results.json'), 'w'), indent=1, default=lambda o: o.item() if hasattr(o, 'item') else str(o))
    flat = []

    def fl_(p, d):
        for k, v in d.items():
            if isinstance(v, dict):
                fl_(p + k + '.', v)
            elif isinstance(v, (int, float, str)):
                flat.append((p + k, v))
    for k in ('capture', 'icmp', 'turnaround_ms', 'req_spacing_s', 'rtt', 'loss', 'tcp'):
        fl_(k + '.', R[k])
    pd.DataFrame(flat, columns=['statistic', 'value']).to_csv(os.path.join(D, 'summary_statistics.csv'), index=False)
    plt.rcParams.update({'font.size': 9, 'axes.spines.top': False, 'axes.spines.right': False, 'figure.dpi': 150})
    C = '#1f77b4'
    C2 = '#d95f02'
    t = pr.req_time.values
    y = rtt[:len(pr)]
    f, ax = plt.subplots(2, 1, figsize=(9, 6), sharex=True)
    ax[0].plot(t, y, lw=0.7, color=C)
    ax[0].axhline(med, color='gray', ls='--', lw=0.8, label=f'median {med:.0f} ms')
    ax[0].set_ylabel('RTT at System A (ms)')
    ax[0].set_title('(a) Network RTT over time (System A ping log)')
    ax[0].legend(frameon=False)
    ax[1].plot(t, iv, lw=0.7, color=C2)
    ax[1].set_ylabel('Request→reply interval at B (ms)')
    ax[1].set_xlabel('Time since first ICMP request (s)')
    ax[1].set_title("(b) Request-to-reply interval in B's capture (B's turnaround time, not network RTT)")
    plt.tight_layout()
    plt.savefig(os.path.join(G, 'graph5_rtt_over_time.png'))
    plt.close()
    f, ax = plt.subplots(1, 2, figsize=(10, 4))
    ax[0].bar(pc.index, pc.packets, color=C)
    ax[0].set_title('(a) Packets by protocol')
    ax[0].set_ylabel('Packets')
    for i, v_ in enumerate(pc.packets):
        ax[0].text(i, v_, f'{pc.pct_packets.iloc[i]:.1f}%', ha='center', va='bottom', fontsize=8)
    ax[1].bar(pc.index, pc.bytes / 1000.0, color=C2)
    ax[1].set_title('(b) Bytes by protocol')
    ax[1].set_ylabel('kB')
    for i, v_ in enumerate(pc.bytes):
        ax[1].text(i, v_ / 1000.0, f'{pc.pct_bytes.iloc[i]:.1f}%', ha='center', va='bottom', fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(G, 'graph1_protocol_distribution.png'))
    plt.close()
    f, ax = plt.subplots(figsize=(9, 3.8))
    ax.plot(c10.index * 10, c10.values, color='#555', lw=0.8, label='All packets')
    ax.plot(i10.index * 10, i10.values, color=C2, lw=1, label='ICMP only')
    ax.set_xlabel('Time since capture start (s)')
    ax.set_ylabel('Packets per 10 s')
    ax.set_title('Packets per 10 s over the capture')
    ax.legend(frameon=False, loc='upper right')
    plt.tight_layout()
    plt.savefig(os.path.join(G, 'graph8_packets_vs_time.png'))
    plt.close()
    f, ax = plt.subplots(figsize=(5, 3.8))
    ax.bar(['Echo requests\n(A→B)', 'Echo replies\n(B→A)'], [len(req), len(rep)], color=[C, C2])
    for i, v_ in enumerate([len(req), len(rep)]):
        ax.text(i, v_, str(v_), ha='center', va='bottom')
    ax.set_ylabel('Packets')
    ax.set_title('Echo request vs reply counts')
    plt.tight_layout()
    plt.savefig(os.path.join(G, 'graph2_request_reply_counts.png'))
    plt.close()
    f, ax = plt.subplots(figsize=(7, 3.8))
    ax.hist(df.length, bins=60, color=C)
    ax.set_yscale('log')
    ax.axvline(74, color=C2, ls='--', label='ICMP echo frame = 74 B')
    ax.set_xlabel('Frame length (bytes)')
    ax.set_ylabel('Packets (log)')
    ax.set_title('Packet length distribution (all traffic)')
    ax.legend(frameon=False)
    plt.tight_layout()
    plt.savefig(os.path.join(G, 'graph4_packet_length_distribution.png'))
    plt.close()
    f, ax = plt.subplots(figsize=(7, 3.8))
    ax.hist(v, bins=np.arange(2.5, v.max() + 1.5, 1), color=C)
    ax.set_yscale('log')
    ax.set_xlabel('RTT (ms, 1 ms resolution)')
    ax.set_ylabel('Pings (log)')
    ax.set_title('RTT distribution (ping log)')
    plt.tight_layout()
    plt.savefig(os.path.join(G, 'graph6_rtt_distribution.png'))
    plt.close()
    f, ax = plt.subplots(figsize=(5, 3.8))
    ax.bar(['Requests (128)', 'Replies (64)'], [int((pr.req_ttl == 128).sum()), int((pr.rep_ttl == 64).sum())], color=[C, C2])
    ax.set_ylabel('Packets')
    ax.set_title('TTL of echo packets')
    plt.tight_layout()
    plt.savefig(os.path.join(G, 'graph3_ttl_distribution.png'))
    plt.close()
    f, ax = plt.subplots(figsize=(7, 3.8))
    ax.hist(gaps, bins=40, color=C)
    ax.set_yscale('log')
    ax.set_xlabel('Gap between successive requests at B (s)')
    ax.set_ylabel('Count (log)')
    ax.set_title('Echo request inter-arrival time')
    plt.tight_layout()
    plt.savefig(os.path.join(G, 'graph7_request_interarrival.png'))
    plt.close()
    print(json.dumps({k: R[k] for k in ('capture', 'icmp', 'turnaround_ms', 'req_spacing_s', 'rtt', 'loss', 'tcp', 'crosscheck', 'bins10', 'longest_gaps', 'rtt_top', 'rtt_blocks')}, indent=1, default=str))
if __name__ == '__main__':
    main()
