# tutil - Type library utilities

Utility to query and build type libraries from files and directories.

## Installation

```
cargo install --path .
```

## Build a type library

Basic usage:

```
tutil build <input>.h <output>
```

...with build arguments:

```
tutil build --clang-arg -DMY_BUILD_ARG=1,-DMY_OTHER_BUILD_ARG=1 <input>.h <output>
```

...with split build arguments:

```
tutil build --clang-arg -DMY_BUILD_ARG=1 --clang-arg -DMY_OTHER_BUILD_ARG=1 <input>.h <output>
```

...with complex 32- and 64-bit build arguments:

```
tutil build --clang-arg32 -DMY_BUILD_ARG=1 --clang-arg64 -DMY_OTHER_BUILD_ARG=1 <input>.h <output>
```

## Query a type library (or header)

Basic usage (dump the whole library):

```
tutil query <input>.<h|bin>
```

...dump 32-bit types:

```
tutil query --bits m32 <input>.<h|bin>
```

...dump 64-bit types to a depth of 3 (unpack 3 levels deep):

```
tutil query --bits m64 --depth 3 <input>.<h|bin>
```

...dump types matching a given prefix:

```
tutil query --prefix <input>.<h|bin>
```

...dump types with a given name:

```
tutil query --exact <exact> <input>.<h|bin>
```

...dump types with a given name and build configuration:

```
tutil query --clang-arg -DMY_BUILD_ARG=1 --exact <exact> <input>.<h|bin>
```
