![build](https://github.com/illikainen/digestlookup/workflows/ci/badge.svg)
![coverage](https://codecov.io/github/illikainen/digestlookup/coverage.svg)
![coverity](https://scan.coverity.com/projects/22409/badge.svg)
![lgtm](https://img.shields.io/lgtm/alerts/github/illikainen/digestlookup.svg)

About
=====

Digestlookup retrieves digests from various package repository metadata.

The downloaded metadata is PGP-verified before it's parsed.  Additionally,
connections to repository mirrors are pinned by their TLS/SSL keys in order
to mitigate the impact of bugs like CVE-2016-1252 and CVE-2019-3462.

The currently supported repositories are APT (Debian, Ubuntu, et al.) and
Portage (Gentoo).


Dependencies
============

On Debian:

```sh
apt-get install \
    build-essential \
    cmake \
    libarchive-dev \
    libcmocka-dev \
    libcurl4-openssl-dev \
    libglib2.0-dev \
    libgpgme-dev \
    liblzma-dev \
    libmicrohttpd-dev
```

While optional, it's also recommended to install `clang` for its minimal
sanitizer runtime that's suitable for use in production.  The minimal
runtime supports [CFI] and [UBSan] (both enabled by default if building
with `clang`).


Build
=====

```sh
make
```


Configuration
=============

See `data/config/digestlookup.conf` for the default configuration.


Usage
=====

```sh
$ ./digestlookup --help
Usage:
  digestlookup [OPTION] patterns...

Help Options:
  -h, --help            Show help options

Application Options:
  -c, --config=path     Configuration file
  -d, --deep            Include package files in the lookup
  -r, --repos=repo      Restrict the lookup to one or more repositories
  -v, --verbose         Show verbose messages
```

```sh
$ ./digestlookup -r apt '^figlet$'
| repository    | package | file                         | algorithm | digest                                                           |
|---------------|---------|------------------------------|-----------|------------------------------------------------------------------|
| debian-stable | figlet  | figlet_2.2.5-3.dsc           | sha256    | f19663ee2437cac166f0d3c4c9bf0d33f0149a6e8f06d6ae80014fd4030bdc81 |
| debian-stable | figlet  | figlet_2.2.5.orig.tar.gz     | sha256    | bf88c40fd0f077dab2712f54f8d39ac952e4e9f2e1882f1195be9e5e4257417d |
| debian-stable | figlet  | figlet_2.2.5-3.debian.tar.xz | sha256    | 38fe48441d93a8c379c73be792d9395f3e6a45c4841783832c7d4f068545e6fb |
```

```sh
$ ./digestlookup '^(app-misc/)?figlet$'
| repository    | package         | file                         | algorithm | digest                                                                                                                           |
|---------------|-----------------|------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------|
| debian-stable | figlet          | figlet_2.2.5-3.dsc           | sha256    | f19663ee2437cac166f0d3c4c9bf0d33f0149a6e8f06d6ae80014fd4030bdc81                                                                 |
| debian-stable | figlet          | figlet_2.2.5.orig.tar.gz     | sha256    | bf88c40fd0f077dab2712f54f8d39ac952e4e9f2e1882f1195be9e5e4257417d                                                                 |
| debian-stable | figlet          | figlet_2.2.5-3.debian.tar.xz | sha256    | 38fe48441d93a8c379c73be792d9395f3e6a45c4841783832c7d4f068545e6fb                                                                 |
| gentoo        | app-misc/figlet | figlet-2.2.5.tar.gz          | sha512    | bb9610fd89a51dd3e65c485653fe1292f47dbca7cb9a05af4ce317f5d776bb346ae455aec07fc37c290f6658639920fd7c431c1135a0f4d456a21c0bd25f99fb |
| gentoo        | app-misc/figlet | figlet.bashcomp-r1           | sha512    | 7140cfbacbd99f0f4e9463bb024ead73ea1a3f6ddf9cb5806134ab711e772f32c57e69596f63f125cf13941cff51f84ccdb9f0288ca8614c99b9f1890d3d3e69 |
| gentoo        | app-misc/figlet | figlet.bashcomp              | sha512    | 1a9d06139bbb105c9d909d1e7bfb64b04d6ccba6e0ebfa0968f75264da5582c2f449ad5759f36ec90bf068e69005c2eac2d0565765b02a13044531601b7b9d18 |
```

The `--deep` option -- while verbose -- is useful for looking up digests for
files that are bundled in other packages, e.g.:

```sh
$ ./digestlookup -r portage --deep 'serde[_-]json'
| repository | package                   | file                                                 | algorithm | digest                                                                                                                           |
|------------|---------------------------|------------------------------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------|
| gentoo     | x11-terms/alacritty       | serde_json-1.0.59.crate                              | sha512    | 2f9bf96fa770f9be9c43fc889e1671e9bb883f49a820aa69a1709d9f679f21f01cef2b771eea4d1fe7994cf850af44577710521fffdc4cc46d0dc6f913842075 |
| gentoo     | x11-terms/alacritty       | serde_json-1.0.56.crate                              | sha512    | ee937a1449701235984a71c9e92035251019d922eccf29e1dc95cdfa008e9bae614650949d8536a5a42ae7b8decfb419b75ec5285b1f85618750efbad24cb11f |
| gentoo     | x11-terms/alacritty       | serde_json-1.0.53.crate                              | sha512    | 8932a9f9f783b7124c7a41c9c3c0c1934c0e5b8b628fc9bab5ae0f78370231649f17de8015f9d6facf4ccd0305c68d8c648799e239bf32558c6be9bbe3819e22 |
| gentoo     | sys-fs/sandboxfs          | serde_json-1.0.52.crate                              | sha512    | 70bf27a8328cd57f0e995a57db97135610cd025c654555e51314309ad2f1b8968c559fa1bb5ca590df138429d0362c6a70a61e17e3aac3c4d7fd02ae4aca4558 |
| gentoo     | sys-apps/ripgrep          | serde_json-1.0.53.crate                              | sha512    | 8932a9f9f783b7124c7a41c9c3c0c1934c0e5b8b628fc9bab5ae0f78370231649f17de8015f9d6facf4ccd0305c68d8c648799e239bf32558c6be9bbe3819e22 |
| gentoo     | sys-apps/bat              | serde_json-1.0.58.crate                              | sha512    | 377a067b1aad851fe7056c080b7a3d07cf6d2c75122766f25b2bf30d6023e70a6f7b5211200019983bfb1f0ac9cf09da4a8c74aef45c819a785818a6ce33ca0a |
| gentoo     | sys-apps/bat              | serde_json-1.0.51.crate                              | sha512    | 0e9e1be1e1c7ef6af2b2b374df6680ccdce149ee7c0641cb518c678b06d72a335321dd857bb1dc64561c3cb090cc1388c7a016fe4cda66da1f1a19e338c1a470 |
| gentoo     | net-libs/quiche           | serde_json-1.0.59.crate                              | sha512    | 2f9bf96fa770f9be9c43fc889e1671e9bb883f49a820aa69a1709d9f679f21f01cef2b771eea4d1fe7994cf850af44577710521fffdc4cc46d0dc6f913842075 |
| gentoo     | net-libs/quiche           | serde_json-1.0.56.crate                              | sha512    | ee937a1449701235984a71c9e92035251019d922eccf29e1dc95cdfa008e9bae614650949d8536a5a42ae7b8decfb419b75ec5285b1f85618750efbad24cb11f |
| gentoo     | net-dns/dog               | serde_json-1.0.59.crate                              | sha512    | 2f9bf96fa770f9be9c43fc889e1671e9bb883f49a820aa69a1709d9f679f21f01cef2b771eea4d1fe7994cf850af44577710521fffdc4cc46d0dc6f913842075 |
| gentoo     | media-video/rav1e         | serde_json-1.0.61.crate                              | sha512    | ff626602b547fa8e48c37251d2f6c91633fd45b49ed8211e66a3174f52f9aafe8778238466e7deb5d5477ed23eea0091596d78894e0967d6978f6737ae115891 |
| gentoo     | media-video/rav1e         | serde_json-1.0.57.crate                              | sha512    | 0ca0ed1cf47c87f907b241e696d6aa23b49bec876d3b9e0e011c20d145b797769631ff8ce8d57487633d1d8a8657e601884bc10b5670ce17c136b9579fd921de |
| gentoo     | media-video/rav1e         | serde_json-1.0.53.crate                              | sha512    | 8932a9f9f783b7124c7a41c9c3c0c1934c0e5b8b628fc9bab5ae0f78370231649f17de8015f9d6facf4ccd0305c68d8c648799e239bf32558c6be9bbe3819e22 |
| gentoo     | gui-libs/greetd           | serde_json-1.0.53.crate                              | sha512    | 8932a9f9f783b7124c7a41c9c3c0c1934c0e5b8b628fc9bab5ae0f78370231649f17de8015f9d6facf4ccd0305c68d8c648799e239bf32558c6be9bbe3819e22 |
| gentoo     | gui-apps/tuigreet         | serde_json-1.0.57.crate                              | sha512    | 0ca0ed1cf47c87f907b241e696d6aa23b49bec876d3b9e0e011c20d145b797769631ff8ce8d57487633d1d8a8657e601884bc10b5670ce17c136b9579fd921de |
| gentoo     | gui-apps/tuigreet         | serde_json-1.0.55.crate                              | sha512    | db81c9ddaae20ff5f712d8a2cbb58a95bfd139d9358797443c9ee10fb8af18f1396faf09f7335c249118feb32f52192734d61efcb0b40204ea58825056eea9c9 |
| gentoo     | dev-util/wasmer           | serde_json-1.0.41.crate                              | sha512    | 63ac513a4813a65962d8f63476ce8e63ce71d1e6643da7443d774078e4a743835276c50c04ce535b2e43251383c537365581838a0bd5d4893a644e396eeec55b |
| gentoo     | dev-util/sccache          | serde_json-1.0.44.crate                              | sha512    | ce1c68bfd2ceaa8b7f45cd34cfbc71dcfe3905b06fa47032403c54aa9eed0e618cd526938eb78dbc201e9480dbd64b4bfb405f2119478229f5cea12056dcf5e4 |
| gentoo     | dev-util/rustup           | serde_json-1.0.59.crate                              | sha512    | 2f9bf96fa770f9be9c43fc889e1671e9bb883f49a820aa69a1709d9f679f21f01cef2b771eea4d1fe7994cf850af44577710521fffdc4cc46d0dc6f913842075 |
| gentoo     | dev-util/rustup           | serde_json-1.0.55.crate                              | sha512    | db81c9ddaae20ff5f712d8a2cbb58a95bfd139d9358797443c9ee10fb8af18f1396faf09f7335c249118feb32f52192734d61efcb0b40204ea58825056eea9c9 |
| gentoo     | dev-util/git-delta        | serde_json-1.0.61.crate                              | sha512    | ff626602b547fa8e48c37251d2f6c91633fd45b49ed8211e66a3174f52f9aafe8778238466e7deb5d5477ed23eea0091596d78894e0967d6978f6737ae115891 |
| gentoo     | dev-util/git-delta        | serde_json-1.0.40.crate                              | sha512    | d09bc95c963f510686106d9885f3420b9eabba8bf32626597dafd43ffbe91ea72ee4a3fedfca922794a727214d73929970acced8eccaa23616cde33dfde9f842 |
| gentoo     | dev-util/cbindgen         | serde_json-1.0.57.crate                              | sha512    | 0ca0ed1cf47c87f907b241e696d6aa23b49bec876d3b9e0e011c20d145b797769631ff8ce8d57487633d1d8a8657e601884bc10b5670ce17c136b9579fd921de |
| gentoo     | dev-util/cargo-license    | serde_json-1.0.44.crate                              | sha512    | ce1c68bfd2ceaa8b7f45cd34cfbc71dcfe3905b06fa47032403c54aa9eed0e618cd526938eb78dbc201e9480dbd64b4bfb405f2119478229f5cea12056dcf5e4 |
| gentoo     | dev-util/cargo-ebuild     | serde_json-1.0.55.crate                              | sha512    | db81c9ddaae20ff5f712d8a2cbb58a95bfd139d9358797443c9ee10fb8af18f1396faf09f7335c249118feb32f52192734d61efcb0b40204ea58825056eea9c9 |
| gentoo     | dev-util/cargo-ebuild     | serde_json-1.0.41.crate                              | sha512    | 63ac513a4813a65962d8f63476ce8e63ce71d1e6643da7443d774078e4a743835276c50c04ce535b2e43251383c537365581838a0bd5d4893a644e396eeec55b |
| gentoo     | dev-util/cargo-c          | serde_json-1.0.48.crate                              | sha512    | 544dd844330a26fbdaeb5246825f143cf06110065089c8be3dc44f8437f797ac083d7dcc5181656ed3d78428fcddc44e6802544ae304466eebdcd625a5a5fef9 |
| gentoo     | dev-util/cargo-audit      | serde_json-1.0.59.crate                              | sha512    | 2f9bf96fa770f9be9c43fc889e1671e9bb883f49a820aa69a1709d9f679f21f01cef2b771eea4d1fe7994cf850af44577710521fffdc4cc46d0dc6f913842075 |
| gentoo     | app-text/fblog            | serde_json-1.0.40.crate                              | sha512    | d09bc95c963f510686106d9885f3420b9eabba8bf32626597dafd43ffbe91ea72ee4a3fedfca922794a727214d73929970acced8eccaa23616cde33dfde9f842 |
| gentoo     | app-misc/rq               | serde_json-1.0.41.crate                              | sha512    | 63ac513a4813a65962d8f63476ce8e63ce71d1e6643da7443d774078e4a743835276c50c04ce535b2e43251383c537365581838a0bd5d4893a644e396eeec55b |
| gentoo     | app-emulation/firecracker | serde_json-1.0.48.crate                              | sha512    | 544dd844330a26fbdaeb5246825f143cf06110065089c8be3dc44f8437f797ac083d7dcc5181656ed3d78428fcddc44e6802544ae304466eebdcd625a5a5fef9 |
| gentoo     | app-benchmarks/hyperfine  | serde_json-1.0.59.crate                              | sha512    | 2f9bf96fa770f9be9c43fc889e1671e9bb883f49a820aa69a1709d9f679f21f01cef2b771eea4d1fe7994cf850af44577710521fffdc4cc46d0dc6f913842075 |
[...]
```


[CFI]: https://clang.llvm.org/docs/ControlFlowIntegrity.html
[UBSan]: https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
