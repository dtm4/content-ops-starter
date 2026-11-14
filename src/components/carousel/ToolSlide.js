import { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import s from './carousel.module.css';
import { download } from './runtime';

const INSERT = {
    shodan: (f) => `shodan ${f} `,
    phoneinfoga: (f) => (f === 'serve' ? 'phoneinfoga serve' : f === '-' ? null : null),
    reconng: (f) => (f === 'run' ? 'run' : `${f} `),
    maltego: () => null
};

export default function ToolSlide({ tool, total, active, onFocusChange }) {
    const [lines, setLines] = useState([]);
    const [input, setInput] = useState(tool.example);
    const [running, setRunning] = useState(false);
    const [exportsMap, setExportsMap] = useState({});
    const [, bump] = useReducer((x) => x + 1, 0);
    const state = useRef(null);
    const history = useRef({ list: [], i: -1 });
    const logRef = useRef(null);
    const inputRef = useRef(null);

    useEffect(() => {
        state.current = tool.initialState ? tool.initialState() : {};
        bump();
    }, [tool]);

    useEffect(() => {
        const el = logRef.current;
        if (el) el.scrollTop = el.scrollHeight;
    }, [lines]);

    const io = useRef(null);
    io.current = {
        print: (text, tone = 'plain', href) => setLines((l) => [...l.slice(-1500), { text: String(text), tone, href }]),
        exports: (map) => setExportsMap(map)
    };
    const ioProxy = useRef({
        print: (...a) => io.current.print(...a),
        exports: (...a) => io.current.exports(...a)
    }).current;

    const prompt = tool.prompt ? tool.prompt(state.current || {}) : '$';

    const run = useCallback(
        async (cmdLine) => {
            const line = (cmdLine ?? input).trim();
            if (!line || running) return;
            const h = history.current;
            h.list = [...h.list.filter((x) => x !== line), line].slice(-50);
            h.i = -1;
            if (line === 'clear' || line === 'cls') {
                setLines([]);
                setInput('');
                return;
            }
            ioProxy.print(`${prompt} ${line}`, 'echo');
            setRunning(true);
            try {
                await tool.exec(line, ioProxy, state.current);
            } catch (e) {
                ioProxy.print(`[!] ${e.status === 429 ? 'Rate limit hit. Wait a minute and retry.' : e.message}`, 'bad');
            } finally {
                setRunning(false);
                if (tool.id === 'reconng' || tool.id === 'maltego') setInput('');
                bump();
            }
        },
        [input, running, tool, prompt, ioProxy]
    );

    const onKeyDown = (e) => {
        const h = history.current;
        if (e.key === 'ArrowUp' && h.list.length) {
            e.preventDefault();
            h.i = h.i < 0 ? h.list.length - 1 : Math.max(0, h.i - 1);
            setInput(h.list[h.i]);
        } else if (e.key === 'ArrowDown' && h.i >= 0) {
            e.preventDefault();
            h.i = h.i + 1 >= h.list.length ? -1 : h.i + 1;
            setInput(h.i < 0 ? '' : h.list[h.i]);
        } else if (e.key === 'l' && e.ctrlKey) {
            e.preventDefault();
            setLines([]);
        }
    };

    const useFlag = (flag) => {
        const custom = INSERT[tool.id];
        let next;
        if (custom) next = custom(flag);
        else if (flag.startsWith('-') && flag.length > 1) next = `${input.replace(/\s+$/, '')} ${flag} `;
        if (next == null) return;
        setInput(next);
        inputRef.current?.focus();
    };

    const Panel = tool.Panel;

    return (
        <article className={s.slide} style={{ '--c': tool.color }} hidden={!active} aria-roledescription="slide" aria-label={`${tool.n} of ${String(total).padStart(2, '0')}: ${tool.name}`}>
            <header className={s.head}>
                <div>
                    <h2 className={s.title}>{tool.name}</h2>
                    <p className={s.sub}>{tool.subtitle}</p>
                </div>
                <div className={s.count}>
                    {tool.n} / {String(total).padStart(2, '0')}
                </div>
            </header>

            <div className={s.term}>
                <div className={s.termBar}>
                    <i style={{ background: '#ff5f57' }} />
                    <i style={{ background: '#febc2e' }} />
                    <i style={{ background: '#28c840' }} />
                    <span>zsh ~ {tool.id === 'reconng' ? 'recon-ng' : tool.id}</span>
                </div>
                <form
                    className={s.cmdRow}
                    onSubmit={(e) => {
                        e.preventDefault();
                        run();
                    }}
                >
                    <label htmlFor={`cmd-${tool.id}`} className={s.prompt}>
                        {prompt}
                    </label>
                    <input
                        id={`cmd-${tool.id}`}
                        ref={inputRef}
                        className={s.cmd}
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={onKeyDown}
                        onFocus={() => onFocusChange?.(true)}
                        onBlur={() => onFocusChange?.(false)}
                        spellCheck={false}
                        autoCapitalize="off"
                        autoComplete="off"
                        autoCorrect="off"
                        enterKeyHint="go"
                        placeholder={tool.example}
                    />
                    <button className={s.runBtn} disabled={running || !input.trim()} aria-label="Run command">
                        {running ? <span className={s.spin} /> : '↵'}
                    </button>
                </form>
                <div className={s.log} ref={logRef} aria-live="polite">
                    <div className={s.comment}># {tool.comment}</div>
                    {lines.map((l, i) =>
                        l.href ? (
                            <a key={i} className={`${s.line} ${s[l.tone] || ''}`} href={l.href} target="_blank" rel="noopener noreferrer nofollow">
                                {l.text}
                            </a>
                        ) : (
                            <div key={i} className={`${s.line} ${s[l.tone] || ''}`}>
                                {l.text || ' '}
                            </div>
                        )
                    )}
                    {running && <div className={`${s.line} ${s.muted}`}>…</div>}
                </div>
                {(Object.keys(exportsMap).length > 0 || lines.length > 0) && (
                    <div className={s.termFoot}>
                        {Object.entries(exportsMap).map(([name, fn]) => (
                            <button key={name} className={s.chipBtn} onClick={() => download(name, fn(), name.endsWith('.csv') ? 'text/csv' : 'application/json')}>
                                ⤓ {name}
                            </button>
                        ))}
                        <button className={s.chipBtn} onClick={() => setLines([])}>
                            clear
                        </button>
                    </div>
                )}
            </div>

            {Panel && state.current && <Panel state={state.current} bump={bump} io={ioProxy} color={tool.color} />}

            <section>
                <h3 className={s.label}>Usage</h3>
                <ul className={s.usage}>
                    {tool.usage.map(([flag, desc]) => (
                        <li key={flag + desc}>
                            <button type="button" className={s.flag} onClick={() => useFlag(flag)} title="Insert into command">
                                {flag}
                            </button>
                            <span>{desc}</span>
                        </li>
                    ))}
                </ul>
            </section>
            <section>
                <h3 className={s.label}>Overview</h3>
                <p className={s.overview}>{tool.overview}</p>
            </section>
        </article>
    );
}
