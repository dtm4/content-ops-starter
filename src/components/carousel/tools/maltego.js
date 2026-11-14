import { useRef, useState } from 'react';
import { tokenize, api, isIp, isDomain, isEmail, toCsv } from '../runtime';
import s from '../carousel.module.css';

// Maltego-style link analysis: entities on a graph, transforms that expand them.

export const ENTITY = {
    domain: { label: 'Domain', color: '#58a6ff', glyph: 'D' },
    dns: { label: 'DNS Name', color: '#b48cff', glyph: 'H' },
    ip: { label: 'IP Address', color: '#3fb950', glyph: 'IP' },
    mx: { label: 'MX Record', color: '#f0883e', glyph: 'MX' },
    ns: { label: 'NS Record', color: '#e8b84a', glyph: 'NS' },
    email: { label: 'Email', color: '#f47fbf', glyph: '@' },
    netblock: { label: 'Netblock', color: '#39c5cf', glyph: 'NB' },
    org: { label: 'Organization', color: '#c9d1d9', glyph: 'O' },
    port: { label: 'Port', color: '#d29922', glyph: 'P' },
    cve: { label: 'Vulnerability', color: '#f85149', glyph: '!' }
};

const toIp = { name: 'To IP Address [DNS]', run: async (v) => ((await api(`/api/osint/resolve/?h=${v}`)).results[v] || []).map((ip) => ['ip', ip]) };

export const TRANSFORMS = {
    domain: [
        {
            name: 'DNS from Domain',
            run: async (v) => {
                const r = await api(`/api/osint/domain/?d=${v}&b=crtsh,hackertarget`);
                return r.hosts
                    .filter((h) => h.host !== v)
                    .sort((a, b) => b.ips.length - a.ips.length)
                    .slice(0, 40)
                    .map((h) => ['dns', h.host]);
            }
        },
        { name: 'To IP Address [DNS]', run: async (v) => (await api(`/api/osint/domain/?d=${v}&b=dns`)).records.A.map((ip) => ['ip', ip]) },
        {
            name: 'To MX / NS records',
            run: async (v) => {
                const r = (await api(`/api/osint/domain/?d=${v}&b=dns`)).records;
                return [...r.MX.map((m) => ['mx', m.split(' ')[1].replace(/\.$/, '')]), ...r.NS.map((n) => ['ns', n])];
            }
        },
        {
            name: 'To Email (Whois)',
            run: async (v) => {
                const [w, d] = await Promise.all([api(`/api/osint/rdap/?q=${v}`).catch(() => ({ emails: [] })), api(`/api/osint/domain/?d=${v}&b=dns`).catch(() => ({ emails: [] }))]);
                return [...new Set([...w.emails, ...d.emails])].map((e) => ['email', e]);
            }
        },
        {
            name: 'To Registrar (Whois)',
            run: async (v) => {
                const w = await api(`/api/osint/rdap/?q=${v}`);
                return w.registrar ? [['org', w.registrar]] : [];
            }
        }
    ],
    dns: [toIp],
    mx: [toIp],
    ns: [toIp],
    ip: [
        {
            name: 'To Netblock',
            run: async (v) => {
                const r = await api(`/api/osint/rdap/?q=${v}`);
                return (r.cidrs.length ? r.cidrs : [r.range]).filter(Boolean).map((c) => ['netblock', c]);
            }
        },
        {
            name: 'To Owner (Whois)',
            run: async (v) => {
                const r = await api(`/api/osint/rdap/?q=${v}`);
                return [r.org || r.name].filter(Boolean).map((o) => ['org', o]);
            }
        },
        {
            name: 'To DNS Name [Reverse]',
            run: async (v) => {
                const r = await api(`/api/osint/ip/?ip=${v}`);
                return [...new Set([...r.reverse, ...(r.internetdb?.hostnames || [])])].map((n) => ['dns', n.replace(/\.$/, '')]);
            }
        },
        { name: 'To Ports (Shodan)', run: async (v) => ((await api(`/api/osint/ip/?ip=${v}`)).internetdb?.ports || []).map((p) => ['port', `${v}:${p}`]) },
        { name: 'To Vulnerabilities (Shodan)', run: async (v) => ((await api(`/api/osint/ip/?ip=${v}`)).internetdb?.vulns || []).map((c) => ['cve', c]) }
    ],
    email: [{ name: 'To Domain', run: async (v) => [['domain', v.split('@')[1]]] }]
};

export function detectEntity(v) {
    v = v.trim().toLowerCase();
    if (isIp(v)) return 'ip';
    if (isEmail(v)) return 'email';
    if (isDomain(v)) return v.split('.').length > 2 ? 'dns' : 'domain';
    return null;
}

export function initialState() {
    return { nodes: [], edges: [], selected: null, busy: null };
}

export function addEntity(state, type, value, parentId) {
    const id = `${type}:${value}`;
    let node = state.nodes.find((n) => n.id === id);
    const parent = parentId && state.nodes.find((n) => n.id === parentId);
    if (!node) {
        const a = Math.random() * Math.PI * 2;
        node = { id, type, value, x: (parent?.x ?? 400) + Math.cos(a) * 60, y: (parent?.y ?? 260) + Math.sin(a) * 60, vx: 0, vy: 0 };
        state.nodes.push(node);
    }
    if (parent && !state.edges.some(([a, b]) => (a === parentId && b === id) || (a === id && b === parentId))) state.edges.push([parentId, id]);
    return node;
}

export function layout(state, iterations = 160, W = 800, H = 520) {
    const N = state.nodes;
    const idx = new Map(N.map((n, i) => [n.id, i]));
    for (let it = 0; it < iterations; it++) {
        const t = 1 - it / iterations;
        for (let i = 0; i < N.length; i++) {
            const a = N[i];
            for (let j = i + 1; j < N.length; j++) {
                const b = N[j];
                let dx = a.x - b.x,
                    dy = a.y - b.y;
                const d2 = dx * dx + dy * dy + 0.01;
                if (d2 > 160000) continue;
                const f = 5200 / d2;
                const d = Math.sqrt(d2);
                dx /= d;
                dy /= d;
                a.vx += dx * f;
                a.vy += dy * f;
                b.vx -= dx * f;
                b.vy -= dy * f;
            }
        }
        for (const [p, c] of state.edges) {
            const a = N[idx.get(p)],
                b = N[idx.get(c)];
            if (!a || !b) continue;
            const dx = b.x - a.x,
                dy = b.y - a.y;
            const d = Math.sqrt(dx * dx + dy * dy) || 1;
            const f = (d - 120) * 0.04;
            a.vx += (dx / d) * f;
            a.vy += (dy / d) * f;
            b.vx -= (dx / d) * f;
            b.vy -= (dy / d) * f;
        }
        for (const n of N) {
            n.vx += (W / 2 - n.x) * 0.004;
            n.vy += (H / 2 - n.y) * 0.004;
            if (!n.pinned) {
                n.x += Math.max(-12, Math.min(12, n.vx)) * t;
                n.y += Math.max(-12, Math.min(12, n.vy)) * t;
            }
            n.vx *= 0.5;
            n.vy *= 0.5;

        }
    }
}

export async function runTransform(state, nodeId, tf, io) {
    const node = state.nodes.find((n) => n.id === nodeId);
    io.print(`[>] ${tf.name} · ${ENTITY[node.type].label}: ${node.value}`, 'accent');
    try {
        const out = await tf.run(node.value);
        let fresh = 0;
        for (const [type, value] of out) {
            const before = state.nodes.length;
            addEntity(state, type, value, nodeId);
            if (state.nodes.length > before) fresh++;
        }
        io.print(`    ${out.length} entities returned (${fresh} new)`, out.length ? 'ok' : 'muted');
    } catch (e) {
        io.print(`    transform failed: ${e.message}`, 'bad');
    }
}

function GraphPanel({ state, bump, io }) {
    const svgRef = useRef(null);
    const [menu, setMenu] = useState(null);
    const drag = useRef(null);
    const vbRef = useRef(null);

    const pt = (e) => {
        const svg = svgRef.current;
        const p = svg.createSVGPoint();
        p.x = e.clientX;
        p.y = e.clientY;
        return p.matrixTransform(svg.getScreenCTM().inverse());
    };

    const openMenu = (e, n) => {
        e.preventDefault();
        e.stopPropagation();
        const r = svgRef.current.parentElement.getBoundingClientRect();
        state.selected = n.id;
        setMenu({ id: n.id, x: Math.min(e.clientX - r.left, r.width - 230), y: e.clientY - r.top });
        bump();
    };

    const run = async (tfs, id) => {
        setMenu(null);
        state.busy = id;
        bump();
        for (const tf of tfs) await runTransform(state, id, tf, io);
        state.busy = null;
        layout(state);
        bump();
    };

    const sel = state.nodes.find((n) => n.id === state.selected);
    const linked = new Set(sel ? [sel.id, ...state.edges.filter((e) => e.includes(sel.id)).flat()] : []);

    if (!state.nodes.length)
        return (
            <div className={s.graphEmpty}>
                Type a domain, IP or email in the terminal and press run. It lands here as an entity. Right-click or tap it to run transforms.
            </div>
        );

    // Fit the view to the graph (keeps a 8:5 frame, at least 420 units wide)
    const xs = state.nodes.map((n) => n.x);
    const ys = state.nodes.map((n) => n.y);
    let [x0, x1, y0, y1] = [Math.min(...xs) - 70, Math.max(...xs) + 70, Math.min(...ys) - 45, Math.max(...ys) + 50];
    let vw = Math.max(420, x1 - x0);
    let vh = Math.max(262, y1 - y0);
    if (vw / vh > 1.6) vh = vw / 1.6;
    else vw = vh * 1.6;
    let vb = [(x0 + x1) / 2 - vw / 2, (y0 + y1) / 2 - vh / 2, vw, vh];
    if (drag.current?.moved && vbRef.current) vb = vbRef.current;
    vbRef.current = vb;

    const counts = state.nodes.reduce((m, n) => ((m[n.type] = (m[n.type] || 0) + 1), m), {});
    return (
        <div className={s.graphWrap} onClick={() => setMenu(null)}>
            <div className={s.graphBar}>
                {Object.entries(counts).map(([t, c]) => (
                    <span key={t} className={s.legend} style={{ color: ENTITY[t].color }}>
                        ● {ENTITY[t].label} {c}
                    </span>
                ))}
                <span className={s.graphHint}>{state.busy ? 'running transform…' : 'tap / right-click an entity · drag to move'}</span>
            </div>
            <svg
                ref={svgRef}
                viewBox={vb.join(' ')}
                className={s.graph}
                onPointerMove={(e) => {
                    if (!drag.current) return;
                    const p = pt(e);
                    Object.assign(drag.current.node, { x: p.x, y: p.y, pinned: true });
                    drag.current.moved = true;
                    bump();
                }}
                onPointerUp={() => {
                    if (drag.current?.moved) setTimeout(bump, 0);
                    drag.current = null;
                }}
                onPointerLeave={() => (drag.current = null)}
            >
                {state.edges.map(([a, b]) => {
                    const A = state.nodes.find((n) => n.id === a);
                    const B = state.nodes.find((n) => n.id === b);
                    if (!A || !B) return null;
                    const on = !sel || (linked.has(a) && linked.has(b));
                    return <line key={a + b} x1={A.x} y1={A.y} x2={B.x} y2={B.y} stroke={on ? '#4a5a6c' : '#1c242e'} strokeWidth={on ? 1.3 : 0.8} />;
                })}
                {state.nodes.map((n) => {
                    const E = ENTITY[n.type];
                    const dim = sel && !linked.has(n.id);
                    const label = n.type === 'port' ? n.value.split(':')[1] : n.value;
                    return (
                        <g
                            key={n.id}
                            transform={`translate(${n.x},${n.y})`}
                            opacity={dim ? 0.25 : 1}
                            className={s.node}
                            onContextMenu={(e) => openMenu(e, n)}
                            onPointerDown={(e) => {
                                e.stopPropagation();
                                drag.current = { node: n, moved: false };
                            }}
                            onClick={(e) => {
                                if (drag.current?.moved) return;
                                openMenu(e, n);
                            }}
                        >
                            <circle r={n.type === 'domain' ? 17 : 13} fill="#0d1117" stroke={E.color} strokeWidth={state.busy === n.id ? 4 : 2} />
                            <text textAnchor="middle" dy="4" fontSize={E.glyph.length > 1 ? 9 : 12} fill={E.color} fontWeight="700">
                                {E.glyph}
                            </text>
                            <text textAnchor="middle" y={n.type === 'domain' ? 32 : 27} fontSize="10.5" fill="#c9d1d9">
                                {label.length > 30 ? label.slice(0, 28) + '…' : label}
                            </text>
                        </g>
                    );
                })}
            </svg>
            {menu && (
                <div className={s.menu} style={{ left: Math.max(4, menu.x), top: menu.y }} onClick={(e) => e.stopPropagation()}>
                    {(() => {
                        const n = state.nodes.find((x) => x.id === menu.id);
                        const tfs = TRANSFORMS[n.type] || [];
                        return (
                            <>
                                <div className={s.menuHead} style={{ color: ENTITY[n.type].color }}>
                                    {ENTITY[n.type].label}: {n.value}
                                </div>
                                {tfs.length > 1 && (
                                    <button className={s.menuItem} onClick={() => run(tfs, n.id)}>
                                        ▶ Run all transforms
                                    </button>
                                )}
                                {tfs.map((tf) => (
                                    <button key={tf.name} className={s.menuItem} onClick={() => run([tf], n.id)}>
                                        {tf.name}
                                    </button>
                                ))}
                                {!tfs.length && <div className={s.menuNone}>No transforms for this entity</div>}
                                <button
                                    className={s.menuItem}
                                    onClick={() => {
                                        state.nodes = state.nodes.filter((x) => x.id !== n.id);
                                        state.edges = state.edges.filter((e) => !e.includes(n.id));
                                        state.selected = null;
                                        setMenu(null);
                                        bump();
                                    }}
                                >
                                    ✕ Delete entity
                                </button>
                            </>
                        );
                    })()}
                </div>
            )}
        </div>
    );
}

export default {
    id: 'maltego',
    n: '03',
    name: 'Maltego',
    color: '#f47fbf',
    subtitle: 'OSINT link-analysis graphs',
    example: 'example.com',
    prompt: () => 'entity ›',
    comment: 'drop in a domain, IP or email → right-click it → run transforms',
    usage: [
        ['DNS from Domain', 'resolve live hosts'],
        ['To Email (Whois)', 'registrant emails'],
        ['To Netblock', 'owned IP ranges'],
        ['•', 'Pivot the graph visually']
    ],
    overview:
        'Maltego turns scattered data into a picture. Drop in a domain, email or IP and run transforms to pull related entities, then watch the links between people, infrastructure and accounts render as a graph you can pivot.',
    initialState,
    Panel: GraphPanel,

    async exec(line, io, state) {
        const argv = tokenize(line);
        const first = (argv[0] || '').toLowerCase();
        if (first === 'clear-graph' || first === 'new') {
            Object.assign(state, initialState());
            return io.print('[*] New graph.', 'muted');
        }
        if (first === 'help') {
            io.print('Type a domain, IP or email to add it as an entity. Then tap or right-click it on the graph to run transforms.');
            io.print('Commands: transform all <entity> · new (empty graph)', 'muted');
            return;
        }
        const autoAll = first === 'transform' && argv[1] === 'all';
        const value = (autoAll ? argv[2] : argv[0] === 'entity' ? argv[1] : argv[0]) || '';
        const type = detectEntity(value);
        if (!type) return io.print(`[!] "${value}" is not a domain, IP or email.`, 'bad');
        const node = addEntity(state, type, value.toLowerCase());
        state.selected = node.id;
        io.print(`[+] ${ENTITY[type].label} entity added: ${node.value}`, 'ok');
        if (autoAll) for (const tf of TRANSFORMS[type] || []) await runTransform(state, node.id, tf, io);
        else io.print('    tap / right-click it on the graph to run transforms', 'muted');
        layout(state);
        io.exports({
            'maltego-graph-entities.csv': () => toCsv(state.nodes.map((n) => ({ type: ENTITY[n.type].label, value: n.value }))),
            'maltego-graph-links.csv': () => toCsv(state.edges.map(([a, b]) => ({ from: a, to: b }))),
            'maltego-graph.json': () => JSON.stringify({ nodes: state.nodes.map(({ id, type, value }) => ({ id, type, value })), edges: state.edges }, null, 2)
        });
    }
};
