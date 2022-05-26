
# ocelot

Parse C headers to identify function prototypes, type declarations, and global variables.

## Components and Features

`ocelot` provides a very simple interface for breaking down C files into their most primitive constituent parts. Given a source file and a list of include directories, the library will produce an exhaustive list of all top-level functions, types, and variables.

`ocelot` also optionally supports parsing and serializing of generated symbol tables via [JSON](https://www.json.org/). This allows for easy interoperability with other tools and languages.

`ocelot-cli` is a simple command-line tool that uses `ocelot` to output JSON symbol tables for target C files.

## Why?

Wouldn't it be nice to be able to just "include" C header files in other languages and have the FFI layer handle all the binding glue for you? FFI implementations can leverage `ocelot` to support this. `ocelot` will provide complete type information, so you don't need to worry about implementing this on your own. `ocelot` can also help out if your compiler is targeting C, in which case you'll be interested in finding the names and types of global variables, structs, and union members.

## What is it not?

`ocelot` is not a fully-fledged AST parser. It does not provide access to macros, function bodies, or even function parameter names. Instead, it gives you all of the type information you need to call a C function from another language.

## API

`ocelot` is simple to use.

```c
#include "ocelot.h"

int main(void)
{
	ocelot_symbols *symbols = ocelot_parse("header.h", 0);
	ocelot_symbol **all_symbols = ocelot_symbols_get_all(symbols);
	ocelot_symbol **itr;
	for (itr = all_symbols; *itr; itr++)
	{
		printf("symbol: `%s`\n", (*itr)->name);
	}
	free(all_symbols);
	ocelot_symbols_delete(symbols);
	return 0;
}
```

See [ocelot.h](src/ocelot.h) for the complete API.

## CLI

```bash
$ ocelot header.h > header.json
```

## JSON Examples

`ocelot` comes with an example JSON symbol table produced from `ocelot.h` itself. Find the example [here](examples/ocelot.h.json).

## Building

First you need to fetch the code:

```bash
$ git clone --recursive https://github.com/keharriso/ocelot.git
```

`ocelot` depends on [LibClang](https://clang.llvm.org/doxygen/group__CINDEX.html). The standard way to build `ocelot` is to use [CMake](https://cmake.org/).

```bash
$ mkdir build
$ cd build
$ cmake ..
$ make
```

JSON support is enabled by default when building with CMake. To disable it, add -DOCELOT_ENABLE_JSON=OFF to the cmake command.

When compiling without CMake, you need to define OCELOT_ENABLE_JSON to enable JSON support.

## License

Copyright (c) 2022 Kevin Harrison, released under the MIT License (see LICENSE for details).
