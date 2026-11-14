import { useState } from 'react';
import ToolLayout, { Terminal, CommandForm, callApi, downloadJson, downloadCsv } from '../../components/osint/ToolLayout';
import LinkGraph from '../../components/osint/LinkGraph';
import s from '../../components/osint/osint.module.css';

export default function DomainPage() {
    const [q, setQ] = useState('');
    const [loading, setLoading] = useState(false);
    const [err, setErr] = useState('');
    const [data, setData] = useState(null);
    const [view, setView] = useState('table');
    const [filter, setFilter] = useState('');

    async function run() {
        setLoading(true);
        setErr('');
        setData(null);
        try {
            setData(await callApi(`/api/osint/domain?d=${encodeURIComponent(q.trim())}`));
        } catch (e) {
            setErr(e.message);
        } finally {
            setLoading(false);
        }
    }

    const hosts = data ? data.hosts.filter((h) => !filter || h.host.includes(filter) || h.ips.some((ip) => ip.includes(filter))) : [];

    return (
        <ToolLayout active="/tools/domain/" title="Domain Recon" subtitle="Email, subdomain and DNS harvester with a link graph" accent="#58a6ff">
            <Terminal title="theharvester">
                <CommandForm cmd="theHarvester -d" placeholder="example.com" value={q} onChange={setQ} onSubmit={run} loading={loading} />
                <div className={s.hint}>
                    Sources: certificate transparency (crt.sh), HackerTarget hostsearch, DNS. Large domains can take 20s or more.
                </div>
                {err && <div className={s.error}>{err}</div>}
            </Terminal>

            {data && (
                <>
                    <div className={s.stats}>
                        <div className={s.stat}>
                            <div className={s.statNum}>{data.hosts.length}</div>
                            <div className={s.statLabel}>hosts found</div>
                        </div>
                        <div className={s.stat}>
                            <div className={s.statNum}>{data.live}</div>
                            <div className={s.statLabel}>resolve to an IP</div>
                        </div>
                        <div className={s.stat}>
                            <div className={s.statNum}>{data.emails.length}</div>
                            <div className={s.statLabel}>emails</div>
                        </div>
                    </div>
                    <p className={s.hint}>
                        {Object.entries(data.sources)
                            .map(([k, v]) => `${k}: ${v}`)
                            .join(' · ')}
                    </p>

                    <div className={s.sectionLabel}>DNS records</div>
                    <dl className={s.kv}>
                        {Object.entries(data.records).map(([k, v]) =>
                            v && (!Array.isArray(v) || v.length) ? (
                                <FragmentKV key={k} k={k} v={Array.isArray(v) ? v : [v]} />
                            ) : null
                        )}
                    </dl>

                    {data.emails.length > 0 && (
                        <>
                            <div className={s.sectionLabel}>Emails</div>
                            <div className={s.chips}>
                                {data.emails.map((e) => (
                                    <span key={e} className={s.chip}>
                                        {e}
                                    </span>
                                ))}
                            </div>
                        </>
                    )}

                    <div className={s.sectionLabel}>
                        Hosts
                        <button className={s.btnGhost} onClick={() => setView(view === 'table' ? 'graph' : 'table')}>
                            {view === 'table' ? 'graph view' : 'table view'}
                        </button>
                        <button
                            className={s.btnGhost}
                            onClick={() => downloadCsv(`${data.domain}-hosts.csv`, data.hosts.map((h) => ({ host: h.host, ips: h.ips, sources: h.sources })))}
                        >
                            export csv
                        </button>
                        <button className={s.btnGhost} onClick={() => downloadJson(`${data.domain}-recon.json`, data)}>
                            export json
                        </button>
                    </div>

                    {view === 'graph' ? (
                        <LinkGraph data={data} />
                    ) : (
                        <>
                            <input className={s.input} style={{ marginBottom: 10, width: '100%' }} placeholder="filter hosts / ips…" value={filter} onChange={(e) => setFilter(e.target.value)} />
                            <div className={s.tableWrap}>
                                <table className={s.table}>
                                    <thead>
                                        <tr>
                                            <th>host</th>
                                            <th>ip</th>
                                            <th>source</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {hosts.map((h) => (
                                            <tr key={h.host}>
                                                <td>{h.host}</td>
                                                <td>{h.ips.length ? h.ips.join(', ') : <span className={s.muted}>unresolved</span>}</td>
                                                <td className={s.muted}>{h.sources.join(', ')}</td>
                                            </tr>
                                        ))}
                                        {!hosts.length && (
                                            <tr>
                                                <td colSpan={3} className={s.muted}>
                                                    No hosts.
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                            <p className={s.hint}>To check what's exposed on an IP, paste it into the IP Exposure tool.</p>
                        </>
                    )}
                </>
            )}
        </ToolLayout>
    );
}

function FragmentKV({ k, v }) {
    return (
        <>
            <dt>{k}</dt>
            <dd>
                {v.map((x, i) => (
                    <div key={i}>{x}</div>
                ))}
            </dd>
        </>
    );
}
