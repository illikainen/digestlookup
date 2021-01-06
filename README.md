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


[CFI]: https://clang.llvm.org/docs/ControlFlowIntegrity.html
[UBSan]: https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
