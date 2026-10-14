---
name: mun-extractor
description: Extract embedded icons, bitmaps, PNGs, JPEGs, manifests, version info, MUI descriptors, and any other assets from Windows .mun (Multi-User Resource) files — the resource-split PE32 modules introduced in Windows 10 RS5+ that hold every icon and bitmap from system DLLs like imageres.dll, shell32.dll, comctl32.dll. Also works on .dll / .exe / .mui / .scr. Includes RT_GROUP_ICON → .ico reconstruction (byte-exact + modern RGBA re-encode), DIB → canvas decoding (1/4/8/24/32bpp with AND-mask alpha), VS_VERSIONINFO parsing, MUI 0xFECDFECD split-file descriptor decoding, PNG/JPEG/GIF/BMP/TGA signature sniffing, an inventory.json generator, and a zero-install browser tool that mines assets locally without uploading the file anywhere. Use this skill whenever the user mentions a .mun file and wants pictures, icons, or resources out of it ("extract icons from imageres.dll.mun", "what's inside this .mun file", "where did the icons go in Windows 11", "extract resources like Resource Hacker from a .mun"), needs to identify or decode an unknown resource format in a .mun, or wants a client-side visual extractor for MUN modules.
license: MIT
---

# .mun extractor — mining resources out of Windows 10+ resource-split PE modules

A `.mun` (Multi-User Resource) file is a PE32 binary that Microsoft introduced in
**Windows 10 RS5 (build 17763)** to split localizable resources out of system
DLLs. The `.dll` keeps the code; the `.mun` keeps the icons, bitmaps, PNGs,
manifests, version info, and a single **MUI split-file descriptor (0xFECDFECD)**
that links the .mun back to the .dll it was split from.

Walk into `C:\Windows\SystemResources\` on any Windows 10/11 box and you will
find hundreds of them: `imageres.dll.mun`, `shell32.dll.mun`, `comctl32.dll.mun`,
`zipfldr.dll.mun`, `wdc.dll.mun`, … Each is a pure-resource PE — no imports, no
exports, no code, just `.rdata` (small) + `.rsrc` (everything else). For
`imageres.dll.mun` on Win11 10.0.22621, the `.rsrc` section is **100% of the
file's 22.6 MB**, holding **3,179 resource leaves** — **365 icon groups** and
**2,781 icon frames** alone, plus 9 PNGs, 9 RT_BITMAP DIBs, 12 string-typed
IMAGE resources, 1 WAVE, 1 VERSION, 1 MUI descriptor.

This skill extracts every one of those leaves, decodes the formats Resource
Hacker *does* understand (PNG, JPEG, BMP, ICO groups, VERSION, MANIFEST) AND
the ones it routinely misses (string-typed resources, the MUI 0xFECDFECD
descriptor, TGA payloads hiding under non-standard type names), and produces a
JSON inventory so nothing is ever lost.

It is a sibling of `scr-extractor` (which mines .scr/.exe/.dll files); the PE
parser, TGA decoder, ICO rebuilder, exact-PNG encoder, DIB→canvas decoder, and
VS_VERSIONINFO parser are byte-for-byte identical and battle-tested against the
Bubbles.scr reverse-engineering session. The MUN skill adds:
**virtualized card rendering** (because imageres.dll.mun has 3,179 leaves and
naive rendering freezes the browser), **type-filter chips** (one click → "show
only ICON" / "show only MUI"), a **summary panel** showing the breakdown by
type, and an **inventory JSON download** button so you can audit what was
extracted without re-running the parse.

## Core knowledge: MUN = PE in 60 seconds

1. **A .mun IS a PE file.** Same `MZ` DOS header, same `PE\0\0` signature, same
   COFF + optional header, same data directories, same section table. Parse
   it with the exact same code you'd use for a .dll.
2. **`.rsrc` is everything.** Data directory **index 2 (RESOURCE)** gives the
   `.rsrc` RVA + size. For a pure-resource .mun, `.rsrc` is typically
   95–100 % of the file. If your PE parser reports `.rsrc` as nearly the whole
   file, you are looking at a resource-split module — treat it as a .mun.
3. **The tree is 3 levels**: Type → Name/ID → Language. Each leaf points at a
   blob via `IMAGE_RESOURCE_DATA_ENTRY { OffsetToData (RVA), Size, CodePage }`.
4. **Names and types are numeric IDs OR UTF-16 strings** — high bit (0x80000000)
   of the name field set → it is an offset to a `u16 length + UTF-16LE` string
   inside `.rsrc`. Standard RT_* numbers are documented, but **string types are
   legal and extremely common in Microsoft's own binaries**: `IMAGE`, `PNG`,
   `WAVE`, `MUI`, and even custom names like `BMP` (which Windows screensavers
   abuse to hide TGA textures — see `scr-extractor`).
5. **The MUI descriptor is the smoking gun.** Every .mun contains exactly one
   resource of string-type `"MUI"` whose first u32 LE is `0xFECDFECD`. That is
   the language-split-file descriptor — two 128-bit hashes that pair this .mun
   with its language-specific `.mui` file. If you see `0xFECDFECD` you are
   holding a MUN module. See `references/mui-descriptor.md`.

## Quick sniffing order for any .mun resource blob

| Check | Signature | Format |
|---|---|---|
| bytes 0..7 | `89 50 4E 47 0D 0A 1A 0A` | PNG |
| byte 0, byte 2 | `b[0]==0 && b[2] in {2,10}` (+ `TRUEVISION-XFILE.` trailer if present) | TGA (raw=2 / RLE=10) |
| bytes 0..1 | `BM` | BMP (DIB) |
| bytes 0..3 | `FF D8 FF` | JPEG |
| bytes 0..6 | `GIF87a` / `GIF89a` | GIF |
| bytes 0..3 + 8..11 | `RIFF` + `WAVE` | WAV audio |
| first u32 LE | `0xFECDFECD` | MUI split-file descriptor |
| whole blob | UTF-16 text starting with `VS_VERSION_INFO` | RT_VERSION |
| whole blob | `<?xml` or `<assembly` | RT_MANIFEST |
| type == 14 | — | RT_GROUP_ICON (`.ico` directory — see pitfalls) |
| type == 3 | — | RT_ICON (DIB frame; height doubled for XOR+AND planes) |
| type == 2 | — | RT_BITMAP (DIB without the `BM` file header) |

## Workflow — pick a route

### Route A: the user wants to extract something themselves → hand them the tool

`assets/extractor.html` is a standalone, dependency-free, fully client-side HTML
page. Copy it anywhere (or serve it via GitHub Pages — an `index.html` twin
works), open it in any modern browser (works offline, `file://` is fine), drop
the `.mun` (or `.dll`/`.exe`/`.mui`) on it. It:

* walks the 3-level resource tree,
* auto-detects PNG / TGA / BMP / WAV / ICO-group / manifest / version / MUI,
* previews images on canvas with an alpha checkerboard (so transparent icons
  don't disappear into the dark background),
* shows a summary panel with the breakdown by type and clickable type-filter
  chips (click "ICON" to see only the 2,781 icon leaves, etc.),
* virtualizes rendering: only the first 120 cards are built; a "Load more…"
  button appends the next 120. Without this, dropping `imageres.dll.mun`
  (3,179 leaves) freezes the browser for ~30 seconds.
* reconstructs `.ico` files from RT_GROUP_ICON + RT_ICON leaves and offers both
  byte-exact and modern RGBA re-encodes (Vista+ viewers reject legacy ≤8bpp
  DIBs — the modern re-encode fixes that),
* downloads everything as PNG / ICO / BMP / WAV / JSON / raw, including an
  "Extract all images" button and an "Inventory JSON" button.

Nothing is uploaded anywhere. Drop it on `file://` and it still works.

### Route B: headless extraction / automation → run the scripts

```bash
pip install pefile
python scripts/extract_mun_assets.py <file.mun> [out_dir]   # walk + sniff + save + inventory
```

`extract_mun_assets.py` walks **every** resource leaf (string types included),
sniffs each blob, saves raw payloads with the right extension, reconstructs
byte-exact `.ico` files for each RT_GROUP_ICON group, parses the MUI
descriptor, and writes `inventory.json` + `summary.json`. It does NOT do
per-pixel DIB→PNG conversion (that is left to the HTML extractor's lazy
renderer) — this keeps it O(N) in leaf count and able to handle huge .mun
files (imageres.dll.mun's 2,781 icon leaves) without OOM. If you need per-frame
PNGs, open the .mun in the HTML extractor and click "Extract all images".

### Route C: the format is unknown or the script says "UNKNOWN"

Read `scr-extractor`'s `references/re-methodology.md` — the disassembly
playbook for finding and understanding the loader. The same approach
(locate the type string in `.rdata`, find `FindResourceW` IAT slots,
byte-scan `.text` for `FF 15 rel32` indirect calls, walk back to the
parser, cross-check format constants) works for any PE binary, .mun
included. For .mun specifically, there usually IS no loader to find —
.mun modules are pure resources and have no `.text` section, so an
UNKNOWN blob is genuinely unidentified and you should reach for the
disassembly of the parent .dll that consumes this .mun (its name is
the .mun's filename with `.mun` stripped).

## Verification standard — what counts as "extracted correctly"

An extraction is not done until it is validated. Three checks, all cheap:

1. **Leaf count agreement**: the Python extractor's `inventory.json` total must
   match what the HTML extractor reports in its `#count` line. For
   `imageres.dll.mun` on Win11 10.0.22621: **3,179 leaves** — both tools, same
   number. If they disagree, the tree walk is wrong.
2. **Type breakdown agreement**: the `by_type` dict in `inventory.json` must
   match the type-filter chip counts in the HTML UI. For imageres.dll.mun:
   `ICON: 2781, GROUP_ICON: 365, IMAGE: 12, PNG: 9, BITMAP: 9, MUI: 1, WAVE: 1,
   VERSION: 1` — both tools, identical.
3. **Visual sanity check**: open a reconstructed `.ico` in a viewer (or just
   click the card in the HTML extractor — it renders every frame on canvas).
   A mis-decoded DIB (wrong row order, BGR/RGB swap, ignored AND mask) still
   "decodes" — it just looks wrong (upside-down, tinted, opaque where it
   should be transparent). For imageres.dll.mun the headliner icons are the
   modern Windows 11 system icons (folder, file, drive, control-panel applets)
   — they should look crisp at 256×256 with proper alpha.

## Pitfalls register (each one cost real debugging time)

- **Mass-leaf virtualization is mandatory.** `imageres.dll.mun` has 3,179 leaves
  — building 3,179 cards at once freezes the browser for ~30 seconds and uses
  ~700 MB. The HTML extractor renders 120 cards at a time and adds a "Load
  more…" button. If you adapt this skill for another mass-leaf file, keep the
  virtualization.
- **Zeroed ICO directory entries** — building an `.ico` by copying the directory
  buffer *before* writing the 16-byte entries into it yields count=N but
  0x0/0-byte entries: apps report "unrecognized ico". Build the full directory
  FIRST, then copy. See `scr-extractor/references/ico-reconstruction.md`.
- **Legacy 1/4/8bpp DIB icons** are valid but rejected by many modern viewers
  (macOS Preview, some image boards). Always also emit a 32bpp PNG-compressed
  "modern RGBA" `.ico` (Vista+ layout) alongside the byte-exact one.
- **DIB icon rows are bottom-up** — an `RT_ICON` frame with positive `biHeight`
  stores its XOR/AND rows bottom-up, same as any DIB. Decoding top-down yields
  vertically flipped icons.
- **Channel order** — DIB/BMP pixels are B, G, R (, A), *not* RGBA. A red/blue
  swap is the classic symptom.
- **Canvas premultiplication** — never validate through `toDataURL()`; compare
  raw pixels or file bytes instead. The bundled exact-PNG encoder writes RGBA
  verbatim (uncompressed DEFLATE stored blocks) so downloads match the source
  payload byte-for-byte.
- **PNG encoders** — a hand-rolled PNG encoder must be **big-endian** (lengths,
  CRC) with `IDAT` in scanline order; byte-swapping lengths was a real bug.
- **MUI descriptor is small but easy to miss.** Every .mun contains exactly one
  `"MUI"`-string-typed resource, ~256 bytes, signature `0xFECDFECD`. Tools that
  only look up standard RT_* types (Resource Hacker included) miss it entirely.
- **`IMAGE` string type ≠ RT_ICON**. Windows 10+ .mun files store "high-color"
  UI illustrations under a custom string-typed resource named `"IMAGE"`, not
  `RT_ICON` (type 3) or `RT_BITMAP` (type 2). The payloads are PNG or JPEG
  inside — sniff the bytes; don't trust the type name.

## Worked example: imageres.dll.mun (reference output)

Verified against Win11 10.0.22621.4319 — both the HTML extractor and
`scripts/extract_mun_assets.py` produce identical numbers.

