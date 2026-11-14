import { useMemo, useState } from 'react';
import s from './osint.module.css';

// Maltego-style link graph: domain -> hosts -> IPs, plus MX/NS/email entities.
// Deterministic radial layout, no dependencies. Click a node to focus its links.

const COLORS = { domain: '#58a6ff', host: '#bc8cff', ip: '#3fb950', mx: '#f0883e', ns: '#e3b341', email: '#ff7eb6' };
const MAX_HOSTS = 60;

export default function LinkGraph({ data }) {
    const [focus, setFocus] = useState(null);

    const { nodes, edges, size } = useMemo(() => {
        const nodes = new Map();
        const edges = [];
        const add = (id, type, label = id) => {
            if (!nodes.has(id)) nodes.set(id, { id, type, label });
            return id;
        };
        const root = add(`d:${data.domain}`, 'domain', data.domain);
        data.records.MX.forEach((m) => edges.push([root, add(`mx:${m}`, 'mx', m.split(' ')[1])]));
        data.records.NS.forEach((n) => edges.push([root, add(`ns:${n}`, 'ns', n)]));
        data.records.A.forEach((ip) => edges.push([root, add(`ip:${ip}`, 'ip', ip)]));
        data.emails.slice(0, 12).forEach((e) => edges.push([root, add(`e:${e}`, 'email', e)]));
        data.hosts
            .filter((h) => h.host !== data.domain)
            .slice(0, MAX_HOSTS)
            .forEach((h) => {
                const hid = add(`h:${h.host}`, 'host', h.host.replace(`.${data.domain}`, ''));
                edges.push([root, hid]);
                h.ips.slice(0, 3).forEach((ip) => edges.push([hid, add(`ip:${ip}`, 'ip', ip)]));
            });

        const list = [...nodes.values()];
        const inner = list.filter((n) => n.type !== 'ip' && n.type !== 'domain');
        const outer = list.filter((n) => n.type === 'ip');
        const size = Math.max(640, Math.min(1400, 360 + Math.max(inner.length, outer.length) * 14));
        const c = size / 2;
        const place = (arr, r, offset = 0) =>
            arr.forEach((n, i) => {
                const a = (i / Math.max(arr.length, 1)) * Math.PI * 2 + offset;
                n.x = c + r * Math.cos(a);
                n.y = c + r * Math.sin(a);
            });
        nodes.get(root).x = c;
        nodes.get(root).y = c;
        place(inner, size * 0.26);
        place(outer, size * 0.43, 0.1);
        return { nodes, edges, size };
    }, [data]);

    const linked = useMemo(() => {
        if (!focus) return null;
        const set = new Set([focus]);
        edges.forEach(([a, b]) => {
            if (a === focus) set.add(b);
            if (b === focus) set.add(a);
        });
        return set;
    }, [focus, edges]);

    const dim = (id) => (linked && !linked.has(id) ? 0.12 : 1);

    return (
        <div>
            <div className={s.chips} style={{ marginBottom: 8 }}>
                {Object.entries(COLORS).map(([k, v]) => (
                    <span key={k} className={s.chip} style={{ color: v }}>
                        ● {k}
                    </span>
                ))}
                {focus && (
                    <button className={s.btnGhost} onClick={() => setFocus(null)}>
                        clear focus
                    </button>
                )}
            </div>
            <svg viewBox={`0 0 ${size} ${size}`} className={s.graph} role="img" aria-label={`Link graph for ${data.domain}`}>
                {edges.map(([a, b], i) => {
                    const A = nodes.get(a);
                    const B = nodes.get(b);
                    const on = !linked || (linked.has(a) && linked.has(b) && (a === focus || b === focus));
                    return <line key={i} x1={A.x} y1={A.y} x2={B.x} y2={B.y} stroke={on ? '#3a4a5c' : '#1a222c'} strokeWidth={on ? 1.2 : 0.6} />;
                })}
                {[...nodes.values()].map((n) => (
                    <g key={n.id} opacity={dim(n.id)} style={{ cursor: 'pointer' }} onClick={() => setFocus(focus === n.id ? null : n.id)}>
                        <circle cx={n.x} cy={n.y} r={n.type === 'domain' ? 14 : 6} fill={COLORS[n.type]} />
                        <text
                            x={n.x}
                            y={n.y + (n.type === 'domain' ? 30 : 17)}
                            textAnchor="middle"
                            fill="#c9d1d9"
                            fontSize={n.type === 'domain' ? 15 : 10}
                            fontFamily="ui-monospace, monospace"
                        >
                            {n.label.length > 28 ? `${n.label.slice(0, 26)}…` : n.label}
                        </text>
                    </g>
                ))}
            </svg>
            {data.hosts.length > MAX_HOSTS && (
                <p className={s.hint}>
                    The graph shows the first {MAX_HOSTS} of {data.hosts.length} hosts. The full list is in the table.
                </p>
            )}
        </div>
    );
}
