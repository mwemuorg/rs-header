# rs-header

Generic executable-header parsers and loaders, extracted from
[mwemu](https://github.com/sha0coder/mwemu). Two front-ends share one design:
parsing produces plain data structs, and binding into guest memory happens
through a small backend trait — never a concrete emulator — so any project can
map and relocate a binary into its own address space.

- **`pe`** — PE32/PE64 headers, sections, imports/exports, relocations and
  resources. The loader is generic over [`pe::PeLoader`].
- **`elf`** — ELF32/ELF64 headers, segments, dynamic symbols and relocations
  (x86-64 + AArch64). The loader is generic over [`elf::ElfLoader`].

```rust
use rs_header::pe::pe64::PE64;
use rs_header::elf::elf64::Elf64;

let raw = std::fs::read("a.exe")?;
let mut pe = PE64::parse("a.exe", &raw);
pe.load(&raw, &mut backend, base);   // maps sections + binds imports via PeLoader

let raw = std::fs::read("a.out")?;
let mut elf = Elf64::parse(&raw)?;
elf.load(&mut backend, "a.out", false, true, base); // maps + relocates via ElfLoader
```

The consumer implements `PeLoader` / `ElfLoader` over its own memory (`map`,
`write_bytes`, `write_qword`, symbol resolution). `libmwemu` does exactly this.

See [`design/`](../design) for the extraction architecture.

## License

GPL-3.0-only
