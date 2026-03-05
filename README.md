# VulHunt Community Edition

VulHunt is a vulnerability hunting framework developed by Binarly's Research
team. It is designed to help security researchers and practitioners identify
vulnerabilities in software binaries and UEFI firmware. VulHunt is built on top
of Binarly's Binary Analysis Inspection Platform (BIAS), which provides a
powerful and flexible environment for analysing and understanding binaries.
VulHunt integrates with the capabilities of the Binarly Transparency Platform
(BTP) to enable large-scale vulnerability management, hunting, and triage
capabilities.

VulHunt Community Edition is a free and open-source version of the VulHunt
engine within the BTP, designed to facilitate community-developed rulepacks and
integrations.

## Building (with cargo-make)

### Prerequisites

```bash
cargo install cargo-make
```

### Building

```bash
cargo make --profile <development|release> build
```

With support for Binary Ninja:

```bash
cargo make --profile <development|release> build --features=bndb
```

### Installation

```bash
cargo make --profile <development|release> install
```

With support for Binary Ninja:

```bash
cargo make --profile <development|release> install --features=bndb
```

## Building (without cargo-make)

### Prerequisites

```bash
git submodule update --init
```

Install LuaJIT with requisite patches:

```bash
git clone https://github.com/LuaJIT/LuaJIT.git -b v2.1
cd LuaJIT
git apply /path/to/vulhunt-ce/patches/luajit-vulhunt.patch
```

For macOS:

```bash
export MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion)
```

For macOS and Linux:

```bash
make BUILDMODE='static'
export LUA_LIB=/path/to/LuaJIT/src/
export LUA_LIB_NAME=luajit
export LUA_LINK=static
```

For Windows:

```bash
cd src
msvcbuild.bat BUILDMODE='static'
set LUA_LIB=C:\path\to\LuaJIT\src\
set LUA_LIB_NAME=lua51
set LUA_LINK=static
```

### Building

```bash
cargo build --release
```

With support for Binary Ninja:

```bash
cargo build --release --features=bndb
```

### Packaging

Prerequisites:

```bash
cargo install cargo-packager
cargo install cargo-make
```

Build packages for the current platform:

```bash
cargo make package --features=...
```
