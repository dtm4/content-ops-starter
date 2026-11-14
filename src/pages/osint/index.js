import { useCallback, useEffect, useRef, useState } from 'react';
import Head from 'next/head';
import ToolSlide from '../../components/carousel/ToolSlide';
import s from '../../components/carousel/carousel.module.css';
import theharvester from '../../components/carousel/tools/theharvester';
import spiderfoot from '../../components/carousel/tools/spiderfoot';
import maltego from '../../components/carousel/tools/maltego';
import sherlock from '../../components/carousel/tools/sherlock';
import shodan from '../../components/carousel/tools/shodan';
import phoneinfoga from '../../components/carousel/tools/phoneinfoga';
import reconng from '../../components/carousel/tools/reconng';

const TOOLS = [theharvester, spiderfoot, maltego, sherlock, shodan, phoneinfoga, reconng];

export default function OsintCarousel() {
    const [i, setI] = useState(0);
    const typing = useRef(false);
    const touch = useRef(null);

    const go = useCallback((n) => {
        const next = (n + TOOLS.length) % TOOLS.length;
        setI(next);
        if (typeof window !== 'undefined') history.replaceState(null, '', `#${TOOLS[next].n}`);
    }, []);

    useEffect(() => {
        const fromHash = () => {
            const idx = TOOLS.findIndex((t) => `#${t.n}` === location.hash || `#${t.id}` === location.hash);
            if (idx >= 0) setI(idx);
        };
        fromHash();
        window.addEventListener('hashchange', fromHash);
        const onKey = (e) => {
            if (typing.current || e.target.closest?.('input, textarea')) return;
            if (e.key === 'ArrowRight') go(i + 1);
            if (e.key === 'ArrowLeft') go(i - 1);
        };
        window.addEventListener('keydown', onKey);
        return () => {
            window.removeEventListener('hashchange', fromHash);
            window.removeEventListener('keydown', onKey);
        };
    }, [i, go]);

    return (
        <div className={s.page}>
            <Head>
                <title>OSINT Field Kit</title>
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <meta name="description" content="Seven OSINT tools as live terminals: theHarvester, SpiderFoot, Maltego, Sherlock, Shodan, PhoneInfoga, recon-ng." />
                <meta name="robots" content="noindex" />
                <link rel="preconnect" href="https://fonts.googleapis.com" />
                <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
                <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&display=swap" rel="stylesheet" />
            </Head>

            <div className={s.top}>
                <span className={s.brand}>~/osint field kit</span>
                <nav className={s.tabs} aria-label="Tools">
                    {TOOLS.map((t, k) => (
                        <button key={t.id} className={k === i ? s.tabOn : s.tab} style={{ '--c': t.color }} onClick={() => go(k)} aria-current={k === i}>
                            {t.n}
                        </button>
                    ))}
                </nav>
            </div>

            <main
                className={s.stage}
                onTouchStart={(e) => {
                    if (e.target.closest('input, svg, .' + s.log)) return;
                    touch.current = { x: e.touches[0].clientX, y: e.touches[0].clientY };
                }}
                onTouchEnd={(e) => {
                    const t = touch.current;
                    touch.current = null;
                    if (!t) return;
                    const dx = e.changedTouches[0].clientX - t.x;
                    const dy = e.changedTouches[0].clientY - t.y;
                    if (Math.abs(dx) > 70 && Math.abs(dx) > Math.abs(dy) * 1.5) go(i + (dx < 0 ? 1 : -1));
                }}
            >
                {TOOLS.map((t, k) => (
                    <ToolSlide key={t.id} tool={t} total={TOOLS.length} active={k === i} onFocusChange={(v) => (typing.current = v)} />
                ))}
            </main>

            <footer className={s.foot}>
                <button className={s.arrow} onClick={() => go(i - 1)} aria-label="Previous tool">
                    ‹ {TOOLS[(i - 1 + TOOLS.length) % TOOLS.length].name}
                </button>
                <div className={s.dots}>
                    {TOOLS.map((t, k) => (
                        <button key={t.id} className={k === i ? s.dotOn : s.dot} style={{ '--c': TOOLS[i].color }} onClick={() => go(k)} aria-label={t.name} />
                    ))}
                </div>
                <button className={s.arrow} onClick={() => go(i + 1)} aria-label="Next tool">
                    {TOOLS[(i + 1) % TOOLS.length].name} ›
                </button>
            </footer>
            <p className={s.legal}>
                Passive OSINT from public sources. Use only on targets you own or are authorised to assess, and follow privacy law (GDPR/CCPA) and each
                source&apos;s terms. Full toolchain: <code>osint-kit/</code> in the repo.
            </p>
        </div>
    );
}
