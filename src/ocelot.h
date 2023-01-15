/*
  The MIT License (MIT)

  Copyright (c) 2022 Kevin Harrison

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#ifndef OCELOT_H
#define OCELOT_H

/* C Types */
typedef struct ocelot_type ocelot_type;

typedef enum
{
	OC_TYPE_VOID,
	OC_TYPE_POINTER,
	OC_TYPE_ARRAY, /* Constant array */
	OC_TYPE_CHAR,
	OC_TYPE_UCHAR,
	OC_TYPE_SHORT,
	OC_TYPE_USHORT,
	OC_TYPE_INT,
	OC_TYPE_UINT,
	OC_TYPE_LONG,
	OC_TYPE_ULONG,
	OC_TYPE_LLONG,
	OC_TYPE_ULLONG,
	OC_TYPE_FLOAT,
	OC_TYPE_DOUBLE,
	OC_TYPE_LDOUBLE,
	OC_TYPE_BOOL,
	OC_TYPE_FUNCTION,
	OC_TYPE_STRUCT,
	OC_TYPE_UNION,
	OC_TYPE_ENUM
} ocelot_type_class;

typedef struct
{ /* A field in a struct or union */
	char *name;        /* Field name */
	ocelot_type *type; /* Field type */
} ocelot_record_field;

typedef struct
{ /* A field of an enum */
	char *name;       /* Field name */
	long long value;  /* Field value */
} ocelot_enum_field;

typedef union
{ /* Extra information about a compound type */
	struct ocelot_pointer_type
	{ /* Pointer information */
		int indirection;        /* The level of indirection (number of *'s) */
		ocelot_type *base_type; /* The base type */
	} pointer;
	struct ocelot_array_type
	{ /* Constant array information */
		int size;               /* The constant size of the array */
		ocelot_type *base_type; /* The base type */
	} array;
	struct ocelot_function_type
	{ /* Function information */
		ocelot_type **parameters; /* NULL-terminated array of parameter types */
		ocelot_type *return_type; /* The function return type */
		int variadic;             /* Whether or not the function is variadic */
	} function;
	ocelot_record_field **record_fields; /* The list of fields for a struct or union type */
	ocelot_enum_field **enum_fields;     /* The list of fields for an enum type */
} ocelot_compound_type;

struct ocelot_type
{ /* A C type */
	char *name;                    /* The name of the type */
	ocelot_type_class type_class;  /* The type class */
	ocelot_compound_type compound; /* Extra data for compound types */
};

/* Symbol table */
typedef struct ocelot_symbols ocelot_symbols;

/* Symbols */
typedef enum
{ /* The type of symbol */
	OC_SYMBOL_FUNCTION, /* A function prototype */
	OC_SYMBOL_TYPE,     /* A type declaration */
	OC_SYMBOL_VARIABLE  /* A static variable */
} ocelot_symbol_class;

typedef enum
{ /* Symbol linkage type */
	OC_SYMBOL_PRIVATE, /* Static scope */
	OC_SYMBOL_PUBLIC,  /* Global scope, defined in file */
	OC_SYMBOL_EXTERN,  /* Global scope, defined outside file */
} ocelot_symbol_linkage;

typedef struct
{ /* A C symbol */
	char *name;                       /* The name of the symbol */
	ocelot_symbol_class symbol_class; /* The type of symbol */
	ocelot_symbol_linkage linkage;    /* The linkage of the symbol */
	int elaborated;                   /* "struct x" vs. "x" */
	ocelot_type *type;                /* The C type of the symbol */
} ocelot_symbol;

/* Locate and parse a given C file into a symbol table
 * `include_dirs` is a NULL-terminated array of include directories
 * Delete the result using `ocelot_symbols_delete` */
ocelot_symbols *ocelot_parse(const char *path, char **include_dirs);

/* Split a colon-delimited string of include directories into a NULL-terminated array
 * Free the result using `ocelot_free_include_dirs` */
char **ocelot_split_include_dirs(const char *include_dirs);

/* Free a NULL-termianted list of include directories */
void ocelot_free_include_dirs(char **include_dirs);

/* Lookup a symbol by name */
ocelot_symbol *ocelot_symbols_get(const ocelot_symbols *symbols, const char *name);

/* Produce a NULL-terminated array of all symbols in the given table
 * Delete the result using `free`; the symbols themeslves will be deleted alongside the table */
ocelot_symbol **ocelot_symbols_get_all(const ocelot_symbols *symbols);

/* Delete a symbol table */
void ocelot_symbols_delete(ocelot_symbols *symbols);

/* Serialize an ocelot symbol table to JSON
 * NOTE: If compiled with OCELOT_ENABLE_JSON=OFF, this function will not work */
char *ocelot_json_serialize(const ocelot_symbols *symbols);

/* Parse an ocelot symbol table from JSON
 * NOTE: If compiled with OCELOT_ENABLE_JSON=OFF, this function will not work */
ocelot_symbols *ocelot_json_parse(const char *json);

#endif /* OCELOT_H */
