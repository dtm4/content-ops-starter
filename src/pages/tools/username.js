import { useState } from 'react';
import ToolLayout, { Terminal, CommandForm, callApi, downloadCsv } from '../../components/osint/ToolLayout';
import s from '../../components/osint/osint.module.css';

const LABEL = { found: 'FOUND', not_found: 'not found', unknown: 'blocked?', error: 'error' };

export default function UsernamePage() {
    const [q, setQ] = useState('');
    const [loading, setLoading] = useState(false);
    const [err, setErr] = useState('');
    const [data, setData] = useState(null);
    const [onlyFound, setOnlyFound] = useState(true);

    async function run() {
        setLoading(true);
        setErr('');
        setData(null);
        try {
            setData(await callApi(`/api/osint/username?u=${encodeURIComponent(q.trim())}`));
        } catch (e) {
            setErr(e.message);
        } finally {
            setLoading(false);
        }
    }

    const rows = data ? data.results.filter((r) => !onlyFound || r.status === 'found') : [];

    return (
        <ToolLayout active="/tools/username/" title="Username Search" subtitle="Username enumeration across 34 sites" accent="#e3b341">
            <Terminal title="sherlock">
                <CommandForm cmd="sherlock" placeholder="johndoe" value={q} onChange={setQ} onSubmit={run} loading={loading} />
                <div className={s.hint}>
                    Checks run server-side in parallel (~5-10s). &quot;blocked?&quot; means the site rate-limited or blocked the check, so verify it
                    by hand.
                </div>
                {err && <div className={s.error}>{err}</div>}
            </Terminal>

            {data && (
                <>
                    <div className={s.stats}>
                        <div className={s.stat}>
                            <div className={s.statNum}>{data.found}</div>
                            <div className={s.statLabel}>candidate profiles</div>
                        </div>
                        <div className={s.stat}>
                            <div className={s.statNum}>{data.checked}</div>
                            <div className={s.statLabel}>sites checked</div>
                        </div>
                    </div>
                    <div className={s.sectionLabel}>
                        Results for {data.username}
                        <button className={s.btnGhost} onClick={() => setOnlyFound(!onlyFound)}>
                            {onlyFound ? 'show all' : 'only found'}
                        </button>
                        <button className={s.btnGhost} onClick={() => downloadCsv(`${data.username}-usernames.csv`, data.results)}>
                            export csv
                        </button>
                    </div>
                    <div className={s.tableWrap}>
                        <table className={s.table}>
                            <thead>
                                <tr>
                                    <th>status</th>
                                    <th>site</th>
                                    <th>profile</th>
                                    <th>http</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows.map((r) => (
                                    <tr key={r.site}>
                                        <td>
                                            <span className={`${s.badge} ${s[r.status === 'error' ? 'error_' : r.status]}`}>{LABEL[r.status]}</span>
                                        </td>
                                        <td>
                                            {r.site} <span className={s.muted}>· {r.category}</span>
                                        </td>
                                        <td>
                                            <a href={r.url} target="_blank" rel="noopener noreferrer nofollow">
                                                {r.url}
                                            </a>
                                        </td>
                                        <td className={s.muted} style={{ whiteSpace: 'nowrap' }}>{r.http ?? '-'}</td>
                                    </tr>
                                ))}
                                {!rows.length && (
                                    <tr>
                                        <td colSpan={4} className={s.muted}>
                                            No profiles found.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                    <p className={s.hint}>
                        A match only means the handle exists on that site. It doesn&apos;t prove it&apos;s the same person, so check bio, avatar and
                        links before you connect profiles.
                    </p>
                </>
            )}
        </ToolLayout>
    );
}
