import { useState } from 'react';
import ToolLayout, { Terminal, CommandForm, callApi, downloadJson } from '../../components/osint/ToolLayout';
import s from '../../components/osint/osint.module.css';

function Chips({ items, render = (x) => x }) {
    if (!items || !items.length) return <span className={s.muted}>none</span>;
    return (
        <div className={s.chips}>
            {items.map((x) => (
                <span key={String(render(x))} className={s.chip}>
                    {render(x)}
                </span>
            ))}
        </div>
    );
}

export default function IpPage() {
    const [q, setQ] = useState('');
    const [loading, setLoading] = useState(false);
    const [err, setErr] = useState('');
    const [data, setData] = useState(null);

    async function run() {
        setLoading(true);
        setErr('');
        setData(null);
        try {
            setData(await callApi(`/api/osint/ip?ip=${encodeURIComponent(q.trim())}`));
        } catch (e) {
            setErr(e.message);
        } finally {
            setLoading(false);
        }
    }

    const idb = data?.internetdb;
    const sh = data?.shodan;

    return (
        <ToolLayout active="/tools/ip/" title="IP Exposure" subtitle="Search engine data for exposed devices" accent="#3fb950">
            <Terminal title="shodan">
                <CommandForm cmd="shodan host" placeholder="198.51.100.23" value={q} onChange={setQ} onSubmit={run} loading={loading} inputMode="decimal" />
                <div className={s.hint}>Reads Shodan&apos;s existing scan data and sends nothing to the target. Public IPv4 only.</div>
                {err && <div className={s.error}>{err}</div>}
            </Terminal>

            {data && (
                <>
                    <div className={s.sectionLabel}>
                        Overview
                        <button className={s.btnGhost} onClick={() => downloadJson(`${data.ip}.json`, data)}>
                            export json
                        </button>
                    </div>
                    <dl className={s.kv}>
                        <dt>ip</dt>
                        <dd>{data.ip}</dd>
                        <dt>reverse dns</dt>
                        <dd>
                            <Chips items={data.reverse} />
                        </dd>
                        {sh && (
                            <>
                                <dt>org / isp</dt>
                                <dd>
                                    {sh.org || '-'} / {sh.isp || '-'}
                                </dd>
                                <dt>asn</dt>
                                <dd>{sh.asn || '-'}</dd>
                                <dt>location</dt>
                                <dd>{[sh.city, sh.country].filter(Boolean).join(', ') || '-'}</dd>
                                <dt>os</dt>
                                <dd>{sh.os || '-'}</dd>
                                <dt>last scan</dt>
                                <dd>{sh.last_update || '-'}</dd>
                            </>
                        )}
                        <dt>sources</dt>
                        <dd className={s.muted}>
                            {Object.entries(data.sources)
                                .map(([k, v]) => `${k}: ${v}`)
                                .join(' · ')}
                        </dd>
                    </dl>

                    {idb ? (
                        <>
                            <div className={s.sectionLabel}>Open ports</div>
                            <Chips items={idb.ports} />
                            <div className={s.sectionLabel}>Hostnames</div>
                            <Chips items={idb.hostnames} />
                            <div className={s.sectionLabel}>Software (CPE)</div>
                            <Chips items={idb.cpes} />
                            <div className={s.sectionLabel}>Tags</div>
                            <Chips items={idb.tags} />
                            <div className={s.sectionLabel}>Known vulnerabilities ({idb.vulns?.length || 0})</div>
                            <Chips
                                items={idb.vulns}
                                render={(v) => v}
                            />
                            {idb.vulns?.length > 0 && (
                                <p className={s.hint}>
                                    CVEs are inferred from version banners and are not verified. Look up each one on{' '}
                                    <a href="https://nvd.nist.gov/vuln/search" target="_blank" rel="noopener noreferrer" style={{ color: 'inherit' }}>
                                        NVD
                                    </a>
                                    .
                                </p>
                            )}
                        </>
                    ) : (
                        <p className={s.hint}>Shodan InternetDB has no record for this IP.</p>
                    )}

                    {sh?.services?.length > 0 && (
                        <>
                            <div className={s.sectionLabel}>Service banners</div>
                            <div className={s.tableWrap}>
                                <table className={s.table}>
                                    <thead>
                                        <tr>
                                            <th>port</th>
                                            <th>service</th>
                                            <th>banner</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {sh.services.map((sv, i) => (
                                            <tr key={i}>
                                                <td>
                                                    {sv.port}/{sv.transport}
                                                </td>
                                                <td>{[sv.product, sv.version].filter(Boolean).join(' ') || '-'}</td>
                                                <td>
                                                    <pre className={s.pre}>{sv.banner}</pre>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </>
                    )}
                </>
            )}
        </ToolLayout>
    );
}
