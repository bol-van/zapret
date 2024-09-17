How to compile native programs for use in OpenWrt
-------------------------------------------------

1) Fetch correct version of OpenWrt

```sh
cd ~
```

* the latest:

```sh
git clone git://git.openwrt.org/openwrt.git
```

* exact version for older devices, e.g., 15.05:

```sh
git clone git://git.openwrt.org/15.05/openwrt.git
```

```sh
cd openwrt
```

2) Feed Initialization and Installation

```sh
./scripts/feeds update -a
./scripts/feeds install -a
```

3) Add `zapret` packages to build root

* Copy package descriptions: copy `compile/openwrt/*` to `~/openwrt`
* Copy source code of `tpws`: copy `tpws` folder to `~/openwrt/package/zapret/tpws`
* Copy source code of `nfq`: copy `nfq` folder to `~/openwrt/package/zapret/nfq`
* Copy source code of `ip2net`: copy `ip2net` folder to `~/openwrt/package/zapret/ip2net`

4) Make a menuconfig

```sh
make menuconfig
```

* Select your target architecture
* Select packages `Network/Zapret/*` as "M"

5) Compile a toolchain

```sh
make toolchain/compile
```

6) Compile packages

```sh
make package/tpws/compile
make package/nfqws/compile
make package/ip2net/compile
make package/mdig/compile
```

7) Get resulting packages

Take your `tpws*.ipk`, `nfqws*.ipk`, `ip2net*.ipk`, `mdig*.ipk` from there, e.g.:

```sh
find bin -name tpws*.ipk
```
