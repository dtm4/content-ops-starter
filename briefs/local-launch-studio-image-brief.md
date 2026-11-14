# Local Launch Studio — AI Image Brief

Source: full read of bizspark.me (home, 3 concept demos, privacy) · Market: USA · Output: prompts for an AI image generator

---

## 1. What we're making (and why)

| Set | Images | Priority | Why |
|---|---|---|---|
| **A. Demo hero photos** | 3 | **Must** | Replace the 3 Unsplash stock photos. They appear 5× on the home page + once per demo page — highest-leverage images on the site. |
| **B. Social / ad creative** | 6 (3 trades × 2 formats) | Should | Owner-at-work portraits with clean negative space for headline text ("Good at what you do. Look the part.") |
| **C. Share (OG) image plate** | 1 | Should | Site has no `og:image` today — links shared on Facebook/iMessage/LinkedIn show no preview. |
| **D. "Your kind of business" extras** | 3 | Nice | Supports the home-page line *"And your kind of business"* — future demos or ads for trades beyond the three. |

**Total: 13 images.** Generate Set A first, approve the look, then reuse the same style block for the rest.

---

## 2. Global style (applies to every prompt)

**Creative direction:** *"Good at what you do."* Real, skilled, unglamorous competence. Neighborhood, not corporate. Warm, calm, honest — matches a brand that refuses to over-promise.

- **Photographic, not illustrated.** Editorial documentary feel, 35mm, natural window/daylight.
- **Hands and craft in focus.** The work is the hero; faces can be partial, turned, or soft.
- **Muted, earthy palettes** that sit under each demo's color theme (see §3). No neon, no heavy saturation.
- **Lived-in American settings:** strip-mall storefronts, older houses, suburban yards — specific, not generic luxury.
- **Diverse, everyday people** — varied ages, ethnicities, body types. Not model-pretty.
- **Negative space** on one side for text overlays.
- **No text, logos, signage, or brand names** anywhere in frame (AI renders them as gibberish).

**Paste this style block at the end of every prompt:**

```
editorial documentary photograph, shot on 35mm film, Kodak Portra 400 tones, soft natural daylight, shallow depth of field, subtle film grain, muted earthy color palette, candid and unposed, authentic American small business, realistic hands, no text, no logos, no signage
```

**Negative prompt (if the tool supports one):**

```
text, letters, words, logo, watermark, signage, brand names, distorted hands, extra fingers, plastic skin, over-smoothed faces, HDR, oversaturated, neon, stock photo smile, looking at camera, corporate office, luxury interior, 3d render, illustration, cartoon
```

---

## 3. Set A — Demo hero photos (must-have)

**Format:** 4:5 portrait master, 1600×2000 px minimum. Keep the subject in the center 60% so it also crops to 16:9 and 1:1.
**Color cue:** each prompt is tuned to that demo's existing palette so the photo blends with the page.

### A1 — Good Form Barbers
Palette on page: deep olive `#242d20`, sage `#c7d9a2`, pale `#f0f1e5`
Replaces alt: *"Barber shaping a haircut"*

```
Close-up of a barber's hands carefully finishing a clean fade with clippers on a client's head, in a small neighborhood barbershop in the United States, client seated in a vintage barber chair wearing a dark cape, warm late-afternoon window light, olive green and sage tones in the walls and cape, worn wooden counter softly blurred in the background, calm focused moment, negative space on the left side of the frame, [STYLE BLOCK]
```

### A2 — Sunday Cleaning Co.
Palette on page: warm brown `#59412c`, peach `#e1b48d`, cream `#fffbf3`
Replaces alt: *"Bright and fresh living space"*

```
A bright, freshly cleaned living room in a modest American craftsman home, morning sun through sheer curtains, cream walls, warm oak floor, a folded linen throw on a simple sofa, a small vase of eucalyptus on a wooden side table, a cleaner's hand in a peach-colored rubber glove just visible at the edge of the frame wiping a windowsill, calm and uncluttered, warm cream and soft terracotta tones, negative space on the left side of the frame, [STYLE BLOCK]
```

### A3 — Groundwork Landscapes
Palette on page: forest `#2e492f`, leaf `#b6cc92`, pale `#f2f3e8`
Replaces alt: *"Lush green garden and neatly tended lawn"*

```
A neatly edged suburban American front lawn and mulched garden bed with hostas and boxwoods, freshly cut stripes in the grass, a landscaper in work boots and canvas pants kneeling at the bed edge planting, face out of frame, early morning soft light, deep forest green and fresh leaf green tones, a modest single-story house softly blurred in the background, negative space in the upper portion of the frame, [STYLE BLOCK]
```

---

## 4. Set B — Social / ad creative

**Formats:** 1:1 (1080×1080) for feed · 9:16 (1080×1920) for Stories/Reels.
**Composition:** subject in the lower or right third; top third kept clean for headline text added in Canva.
Generate each prompt twice — once per aspect ratio.

### B1 — Barber owner
```
Portrait of a Black barber in his 40s standing in the doorway of his small neighborhood barbershop in the United States, arms relaxed, clippers in hand, quiet confident expression looking slightly off camera, olive and sage tones, soft daylight, large clean area of plain wall above him for text, [STYLE BLOCK]
```

### B2 — Cleaning business owner
```
Portrait of a Latina woman in her 30s, owner of a home cleaning business, standing in a sunlit kitchen of a client's home holding a caddy of cleaning supplies, relaxed genuine half-smile looking slightly off camera, cream and warm terracotta tones, soft window light, large clean area of plain wall above her for text, [STYLE BLOCK]
```

### B3 — Landscaper owner
```
Portrait of a white landscaper in his 50s with a weathered face and work gloves, leaning on a rake beside his pickup truck at the curb of a tidy suburban yard in the American Midwest, looking slightly off camera, forest and leaf green tones, soft morning light, large area of open sky above him for text, [STYLE BLOCK]
```

---

## 5. Set C — Share (OG) image background

**Format:** 1.91:1, 1200×630 px. Generate as a **background plate only**, then add the logo, *"Good at what you do. Look the part."* and *"$299"* in Canva using Bricolage Grotesque + Instrument Serif italic, ink `#20211e` on cream `#f7f6f0`, accent blue `#2148ff`.

```
A row of small independent storefronts on a quiet American main street in soft morning light, a barbershop, a cleaning service and a garden supply shop side by side, awnings and potted plants, no readable signs, warm cream and muted green tones, wide composition with a large empty area of pale sky and wall on the left half for text, [STYLE BLOCK]
```

---

## 6. Set D — "Your kind of business" extras (optional)

Same 4:5 format as Set A.

```
D1 — Close-up of a hairstylist's hands sectioning and curling a client's hair in a small independent salon, warm blush and cream tones, soft window light, [STYLE BLOCK]
```
```
D2 — A handyman's hands fitting a new cabinet hinge in a sunlit kitchen of an older American home, tool belt visible, warm wood and slate blue tones, [STYLE BLOCK]
```
```
D3 — A mobile dog groomer gently drying a golden retriever inside a clean grooming van, soft natural light, warm cream and sky blue tones, [STYLE BLOCK]
```

---

## 7. Tool notes

- **Recommended:** a photoreal model (e.g. via Higgsfield, which is connected). Generate 4 variants per prompt, then pick one.
- **Consistency:** lock the seed from the approved A1 image and reuse it for A2/A3 if your tool allows.
- **Hands check:** zoom in on every hand before approving. Regenerate if fingers are off.
- **Text check:** reject any output with fake lettering on signs, capes, or bottles.
- **Export:** WebP at quality 85 for the site; keep a full-resolution PNG master.

---

## 8. Must-do when publishing

- **Update the on-page label.** Each demo currently says *"A design concept with illustrative stock photography."* Change it to **"A design concept with AI-generated illustrative imagery."**
- **Never present AI people as real clients or testimonials.** The site is careful to label demos as fictional; keep that standard in ads too.
- **Write new alt text** for each image describing what is actually shown.
- **Add the OG image** with `<meta property="og:image">`, `og:image:width` 1200 and `og:image:height` 630.
