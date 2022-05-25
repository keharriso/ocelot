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

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <clang-c/Index.h>

#include "ocelot.h"

const unsigned OC_SYMBOL_TABLE_INITIAL_BUCKETS = 64;
const double OC_SYMBOL_TABLE_MAX_LOAD = 0.77;

typedef struct ocelot_symbol_chain
{
	ocelot_symbol *symbol;
	uint64_t hash;
	struct ocelot_symbol_chain *next;
} ocelot_symbol_chain;

struct ocelot_symbols
{
	uint32_t bucket_count;
	uint32_t entry_count;
	ocelot_symbol_chain **buckets;
};

static char *ocelot_strdup(const char *str)
{
	if (str == NULL) return NULL;
	size_t len = strlen(str) + 1;
	char *dup = (char*) malloc(len);
	if (dup != NULL) memcpy(dup, str, len);
	return dup;
}

static char *ocelot_find_file(const char *name, char *dirs[])
{
	FILE *file;
	if ((file = fopen(name, "r")))
	{
		fclose(file);
		return ocelot_strdup(name);
	}
	size_t name_len = strlen(name);
	char **dir;
	for (dir = dirs; *dir != NULL; dir++)
	{
		size_t dirlen = strlen(*dir);
		char *path = malloc(dirlen + name_len + 2);
		memcpy(path, *dir, dirlen);
		path[dirlen] = '/';
		memcpy(path + dirlen + 1, name, name_len);
		path[dirlen + name_len + 1] = '\0';
		if ((file = fopen(path, "r")))
		{
			fclose(file);
			return path;
		}
		free(path);
	}
	return NULL;
}

static ocelot_type_class ocelot_type_from_clang(enum CXTypeKind type)
{
	switch (type)
	{
	case CXType_Void:
		return OC_TYPE_VOID;
	case CXType_Char_S:
	case CXType_SChar:
		return OC_TYPE_CHAR;
	case CXType_UChar:
		return OC_TYPE_UCHAR;
	case CXType_Short:
		return OC_TYPE_SHORT;
	case CXType_UShort:
		return OC_TYPE_USHORT;
	case CXType_Int:
		return OC_TYPE_INT;
	case CXType_UInt:
		return OC_TYPE_UINT;
	case CXType_Long:
		return OC_TYPE_LONG;
	case CXType_ULong:
		return OC_TYPE_ULONG;
	case CXType_LongLong:
		return OC_TYPE_LLONG;
	case CXType_ULongLong:
		return OC_TYPE_ULLONG;
	case CXType_Float:
		return OC_TYPE_FLOAT;
	case CXType_Double:
		return OC_TYPE_DOUBLE;
	case CXType_LongDouble:
		return OC_TYPE_LDOUBLE;
	case CXType_Enum:
		return OC_TYPE_ENUM;
	case CXType_Bool:
		return OC_TYPE_BOOL;
	case CXType_Record:
	case CXType_Elaborated:
		return OC_TYPE_STRUCT;
	default:
		return OC_TYPE_VOID;
	}
}

static void ocelot_type_delete(ocelot_type *type);

static ocelot_type *ocelot_type_dup(const ocelot_type *type);

static void ocelot_record_field_delete(ocelot_record_field *field)
{
	if (field != NULL)
	{
		free(field->name);
		ocelot_type_delete(field->type);
		free(field);
	}
}

static ocelot_type *ocelot_type_new(ocelot_type_class type_class)
{
	ocelot_type *type = (ocelot_type*) malloc(sizeof(ocelot_type));
	if (type == NULL) return NULL;
	type->name = NULL;
	type->type_class = type_class;
	switch (type->type_class)
	{
	case OC_TYPE_POINTER:
		type->compound.pointer.indirection = 0;
		type->compound.pointer.base_type = NULL;
		break;
	case OC_TYPE_ARRAY:
		type->compound.array.size = 0;
		type->compound.array.base_type = NULL;
		break;
	case OC_TYPE_FUNCTION:
		type->compound.function.parameters = NULL;
		type->compound.function.return_type = NULL;
		type->compound.function.variadic = 0;
		break;
	case OC_TYPE_STRUCT:
	case OC_TYPE_UNION:
		type->compound.record_fields = NULL;
		break;
	case OC_TYPE_ENUM:
		type->compound.enum_fields = NULL;
		break;
	default:
		break;
	}
	return type;
}

static ocelot_type **ocelot_type_list_dup(ocelot_type **list)
{
	if (list == NULL) return NULL;
	ocelot_type **itr;
	size_t size, i;
	for (itr = list, size = 0; *itr != NULL; itr++, size++);
	ocelot_type **new_list = malloc(sizeof(ocelot_type*) * (size + 1));
	if (new_list == NULL) goto cleanup;
	for (itr = list, i = 0; *itr != NULL; itr++, i++)
	{
		new_list[i] = ocelot_type_dup(*itr);
		if (new_list[i] == NULL)
		{
			new_list[++i] = NULL;
			goto cleanup;
		}
	}
	new_list[size] = NULL;
	return new_list;
cleanup:
	if (new_list != NULL)
	{
		for (itr = new_list; *itr != NULL; itr++)
		{
			ocelot_type_delete(*itr);
		}
		free(new_list);
	}
	return NULL;
}

static ocelot_record_field *ocelot_record_field_new(const char *name)
{
	ocelot_record_field *field = (ocelot_record_field*) malloc(sizeof(ocelot_record_field));
	if (field == NULL) goto cleanup;
	field->type = NULL;
	field->name = ocelot_strdup(name);
	if (field->name == NULL) goto cleanup;
	return field;
cleanup:
	ocelot_record_field_delete(field);
	return NULL;
}

static ocelot_record_field *ocelot_record_field_dup(ocelot_record_field *field)
{
	if (field == NULL) return NULL;
	ocelot_record_field *new_field = ocelot_record_field_new(field->name);
	if (new_field == NULL) goto cleanup;
	new_field->type = ocelot_type_dup(field->type);
	if (new_field->type == NULL) goto cleanup;
	return new_field;
cleanup:
	ocelot_record_field_delete(new_field);
	return NULL;
}

static ocelot_record_field **ocelot_record_field_list_dup(ocelot_record_field **list)
{
	if (list == NULL) return NULL;
	ocelot_record_field **itr;
	size_t size, i;
	for (itr = list, size = 0; *itr != NULL; itr++, size++);
	ocelot_record_field **new_list = malloc(sizeof(ocelot_record_field*) * (size + 1));
	if (new_list == NULL) return NULL;
	for (itr = list, i = 0; *itr != NULL; itr++, i++)
	{
		new_list[i] = ocelot_record_field_dup(*itr);
	}
	new_list[size] = NULL;
	return new_list;
}

static void ocelot_enum_field_delete(ocelot_enum_field *field)
{
	if (field != NULL)
	{
		free(field->name);
		free(field);
	}
}

static ocelot_enum_field *ocelot_enum_field_new(const char *name, long long value)
{
	ocelot_enum_field *field = (ocelot_enum_field*) malloc(sizeof(ocelot_enum_field));
	if (field != NULL)
	{
		field->value = value;
		field->name = ocelot_strdup(name);
		if (field->name == NULL)
		{
			free(field);
			field = NULL;
		}
	}
	return field;
}

static ocelot_enum_field *ocelot_enum_field_dup(ocelot_enum_field *field)
{
	if (field == NULL) return NULL;
	ocelot_enum_field *dup = (ocelot_enum_field*) malloc(sizeof(ocelot_enum_field));
	if (dup == NULL) goto cleanup;
	dup->name = ocelot_strdup(field->name);
	if (dup->name == NULL) goto cleanup;
	dup->value = field->value;
	return dup;
cleanup:
	ocelot_enum_field_delete(dup);
	return NULL;
}

static ocelot_enum_field **ocelot_enum_field_list_dup(ocelot_enum_field **list)
{
	if (list == NULL) return NULL;
	ocelot_enum_field **itr;
	size_t size, i;
	for (itr = list, size = 0; *itr != NULL; itr++, size++);
	ocelot_enum_field **new_list = malloc(sizeof(ocelot_enum_field*) * (size + 1));
	if (new_list == NULL) return NULL;
	for (itr = list, i = 0; *itr != NULL; itr++, i++)
	{
		new_list[i] = ocelot_enum_field_dup(*itr);
	}
	new_list[size] = NULL;
	return new_list;
}

static ocelot_type *ocelot_type_dup(const ocelot_type *type)
{
	if (type == NULL) return NULL;
	ocelot_type *new_type = ocelot_type_new(type->type_class);
	if (new_type == NULL) return NULL;
	if (type->name != NULL)
	{
		new_type->name = ocelot_strdup(type->name);
		if (new_type->name == NULL)
		{
			new_type->type_class = OC_TYPE_VOID;
			ocelot_type_delete(new_type);
			return NULL;
		}
	}
	switch (type->type_class)
	{
	case OC_TYPE_POINTER:
		new_type->compound.pointer.indirection = type->compound.pointer.indirection;
		new_type->compound.pointer.base_type = ocelot_type_dup(type->compound.pointer.base_type);
		break;
	case OC_TYPE_ARRAY:
		new_type->compound.array.size = type->compound.array.size;
		new_type->compound.array.base_type = ocelot_type_dup(type->compound.array.base_type);
		break;
	case OC_TYPE_FUNCTION:
		new_type->compound.function.parameters = ocelot_type_list_dup(type->compound.function.parameters);
		new_type->compound.function.return_type = ocelot_type_dup(type->compound.function.return_type);
		new_type->compound.function.variadic = type->compound.function.variadic;
		break;
	case OC_TYPE_STRUCT:
	case OC_TYPE_UNION:
		new_type->compound.record_fields = ocelot_record_field_list_dup(type->compound.record_fields);
		break;
	case OC_TYPE_ENUM:
		new_type->compound.enum_fields = ocelot_enum_field_list_dup(type->compound.enum_fields);
		break;
	default:
		break;
	}
	return new_type;
}

static void ocelot_type_list_delete(ocelot_type **list)
{
	if (list != NULL)
	{
		ocelot_type **itr;
		for (itr = list; *itr != NULL; itr++)
		{
			ocelot_type_delete(*itr);
		}
		free(list);
	}
}

static void ocelot_record_field_list_delete(ocelot_record_field **list)
{
	if (list != NULL)
	{
		ocelot_record_field **itr;
		for (itr = list; *itr != NULL; itr++)
		{
			ocelot_record_field_delete(*itr);
		}
		free(list);
	}
}

static void ocelot_enum_field_list_delete(ocelot_enum_field **list)
{
	if (list != NULL)
	{
		ocelot_enum_field **itr;
		for (itr = list; *itr != NULL; itr++)
		{
			ocelot_enum_field_delete(*itr);
		}
		free(list);
	}
}

static void ocelot_type_delete(ocelot_type *type)
{
	if (type != NULL)
	{
		switch (type->type_class)
		{
		case OC_TYPE_POINTER:
			ocelot_type_delete(type->compound.pointer.base_type);
			break;
		case OC_TYPE_ARRAY:
			ocelot_type_delete(type->compound.array.base_type);
			break;
		case OC_TYPE_FUNCTION:
			ocelot_type_list_delete(type->compound.function.parameters);
			ocelot_type_delete(type->compound.function.return_type);
			break;
		case OC_TYPE_STRUCT:
		case OC_TYPE_UNION:
			ocelot_record_field_list_delete(type->compound.record_fields);
			break;
		case OC_TYPE_ENUM:
			ocelot_enum_field_list_delete(type->compound.enum_fields);
			break;
		default:
			break;
		}
		free(type->name);
		free(type);
	}
}

static void ocelot_clear_compound(ocelot_type *type)
{
	if (type != NULL)
	{
		switch (type->type_class)
		{
		case OC_TYPE_POINTER:
			ocelot_type_delete(type->compound.pointer.base_type);
			type->compound.pointer.base_type = NULL;
			break;
		case OC_TYPE_ARRAY:
			ocelot_type_delete(type->compound.array.base_type);
			type->compound.array.base_type = NULL;
			break;
		case OC_TYPE_FUNCTION:
			ocelot_type_list_delete(type->compound.function.parameters);
			type->compound.function.parameters = NULL;
			ocelot_type_delete(type->compound.function.return_type);
			type->compound.function.return_type = NULL;
			break;
		case OC_TYPE_STRUCT:
		case OC_TYPE_UNION:
			ocelot_record_field_list_delete(type->compound.record_fields);
			type->compound.record_fields = NULL;
			break;
		case OC_TYPE_ENUM:
			ocelot_enum_field_list_delete(type->compound.enum_fields);
			type->compound.enum_fields = NULL;
			break;
		default:
			break;
		}
	}
}

static void ocelot_symbol_delete(ocelot_symbol *symbol)
{
	if (symbol != NULL)
	{
		free(symbol->name);
		ocelot_type_delete(symbol->type);
		free(symbol);
	}
}

static ocelot_symbol *ocelot_symbol_new(ocelot_symbol_class symbol_class, const char *name)
{
	ocelot_symbol *symbol = (ocelot_symbol*) malloc(sizeof(ocelot_symbol));
	if (symbol == NULL) goto cleanup;
	symbol->symbol_class = symbol_class;
	symbol->elaborated = 0;
	symbol->name = NULL;
	symbol->type = NULL;
	symbol->name = ocelot_strdup(name);
	if (symbol->name == NULL && name != NULL) goto cleanup;
	symbol->linkage = OC_SYMBOL_PRIVATE;
	return symbol;
cleanup:
	ocelot_symbol_delete(symbol);
	return NULL;
}

static ocelot_symbol *ocelot_symbol_dup(ocelot_symbol *symbol)
{
	ocelot_symbol *dup = NULL;
	if (symbol != NULL)
	{
		dup = ocelot_symbol_new(symbol->symbol_class, symbol->name);
		if (dup != NULL)
		{
			dup->linkage = symbol->linkage;
			dup->elaborated = symbol->elaborated;
			dup->type = ocelot_type_dup(symbol->type);
			if (dup->type == NULL)
			{
				ocelot_symbol_delete(dup);
				dup = NULL;
			}
		}
	}
	return dup;
}

static void ocelot_symbol_chain_delete(ocelot_symbol_chain *chain)
{
	if (chain != NULL)
	{
		ocelot_symbol_delete(chain->symbol);
		ocelot_symbol_chain_delete(chain->next);
		free(chain);
	}
}

static ocelot_symbol_chain *ocelot_symbol_chain_new(ocelot_symbol *symbol, uint64_t hash)
{
	ocelot_symbol_chain *chain = (ocelot_symbol_chain*) malloc(sizeof(ocelot_symbol_chain));
	if (chain == NULL) goto cleanup;
	chain->next = NULL;
	chain->symbol = symbol;
	chain->hash = hash;
	return chain;
cleanup:
	ocelot_symbol_chain_delete(chain);
	return NULL;
}

static ocelot_symbols *ocelot_symbols_new(void)
{
	ocelot_symbols *symbols = (ocelot_symbols*) malloc(sizeof(ocelot_symbols));
	if (symbols == NULL) goto cleanup;
	symbols->bucket_count = OC_SYMBOL_TABLE_INITIAL_BUCKETS;
	symbols->entry_count = 0;
	symbols->buckets = (ocelot_symbol_chain**) calloc(OC_SYMBOL_TABLE_INITIAL_BUCKETS, sizeof(ocelot_symbol_chain*));
	if (symbols->buckets == NULL) goto cleanup;
	return symbols;
cleanup:
	ocelot_symbols_delete(symbols);
	return NULL;
}

void ocelot_symbols_delete(ocelot_symbols *symbols)
{
	if (symbols != NULL)
	{
		if (symbols->buckets != NULL)
		{
			unsigned i;
			for (i = 0; i < symbols->bucket_count; i++)
			{
				ocelot_symbol_chain_delete(symbols->buckets[i]);
			}
			free(symbols->buckets);
		}
		free(symbols);
	}
}

/* https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function */
static uint64_t ocelot_symbols_hash(const char *str)
{
	uint64_t hash = 0xcbf29ce484222325;
	while (*str)
	{
		hash *= 0x100000001b3;
		hash ^= *(str++);
	}
	return hash;
}

static ocelot_symbol_chain **ocelot_symbols_find_chain(const ocelot_symbols *symbols, const char *name, uint64_t *hash_out)
{
	uint64_t hash = ocelot_symbols_hash(name);
	if (hash_out != NULL)
	{
		*hash_out = hash;
	}
	ocelot_symbol_chain **chain;
	for (chain = &symbols->buckets[hash % symbols->bucket_count]; *chain != NULL; chain = &(*chain)->next)
	{
		if ((*chain)->hash == hash && !strcmp((*chain)->symbol->name, name))
		{
			return chain;
		}
	}
	return chain;
}

static void ocelot_symbols_resize(ocelot_symbols *symbols, uint32_t bucket_count)
{
	ocelot_symbol_chain **old_buckets = symbols->buckets;
	uint32_t old_bucket_count = symbols->bucket_count;
	symbols->buckets = calloc(bucket_count, sizeof(ocelot_symbol_chain*));
	if (symbols->buckets == NULL) goto cleanup;
	symbols->bucket_count = bucket_count;
	uint32_t i, j;
	for (i = 0; i < old_bucket_count; i++)
	{
		ocelot_symbol_chain *chain = old_buckets[i];
		while (chain != NULL)
		{
			j = chain->hash % bucket_count;
			ocelot_symbol_chain *target = symbols->buckets[j];
			ocelot_symbol_chain *next = chain->next;
			chain->next = target;
			symbols->buckets[j] = chain;
			chain = next;
		}
	}
	free(old_buckets);
	return;
cleanup:
	symbols->buckets = old_buckets;
	return;
}

static int ocelot_type_equivalent(ocelot_type *a, ocelot_type *b);

static int ocelot_type_list_equivalent(ocelot_type **a, ocelot_type **b)
{
	if (a == NULL && b == NULL)
	{
		return 1;
	}
	else if (a == NULL || b == NULL)
	{
		return 0;
	}
	while (*a && *b)
	{
		if (!ocelot_type_equivalent(*(a++), *(b++)))
		{
			return 0;
		}
	}
	return *a == *b;
}

static int ocelot_record_field_list_equivalent(ocelot_record_field **a, ocelot_record_field **b)
{
	while (*a && *b)
	{
		if (strcmp((*a)->name, (*b)->name) || !ocelot_type_equivalent((*(a++))->type, (*(b++))->type))
		{
			return 0;
		}
	}
	return *a == *b;
}

static int ocelot_type_is_atomic(ocelot_type_class tc)
{
	return tc != OC_TYPE_POINTER && tc != OC_TYPE_ARRAY && tc != OC_TYPE_FUNCTION
		&& tc != OC_TYPE_STRUCT && tc != OC_TYPE_UNION && tc != OC_TYPE_ENUM;
}

static int ocelot_type_equivalent(ocelot_type *a, ocelot_type *b)
{
	int equivalent = 0;
	if (a == NULL || b == NULL)
	{
		equivalent = 0;
		goto cleanup;
	}
	if (a->type_class != b->type_class)
	{
		equivalent = 0;
		goto cleanup;
	}
	if (ocelot_type_is_atomic(a->type_class) && ocelot_type_is_atomic(b->type_class) && a->type_class == b->type_class)
	{
		equivalent = 1;
		goto cleanup;
	}
	ocelot_type_class type_class = a->type_class;
	switch (type_class)
	{
	case OC_TYPE_POINTER:
		equivalent = a->compound.pointer.indirection == b->compound.pointer.indirection &&
			ocelot_type_equivalent(a->compound.pointer.base_type, b->compound.pointer.base_type);
		break;
	case OC_TYPE_ARRAY:
		equivalent = a->compound.array.size == b->compound.array.size &&
			ocelot_type_equivalent(a->compound.array.base_type, b->compound.array.base_type);
		break;
	case OC_TYPE_FUNCTION:
		if ((a->compound.function.parameters == NULL || a->compound.function.parameters[0] == NULL) && a->compound.function.return_type == NULL)
		{
			free(a->compound.function.parameters);
			a->compound.function.parameters = ocelot_type_list_dup(b->compound.function.parameters);
			a->compound.function.return_type = ocelot_type_dup(b->compound.function.return_type);
			a->compound.function.variadic = b->compound.function.variadic;
			equivalent = 1;
		}
		else if ((b->compound.function.parameters == NULL || b->compound.function.parameters[0] == NULL) && b->compound.function.return_type == NULL)
		{
			equivalent = 1;
		}
		else
		{
			equivalent = a->compound.function.variadic == b->compound.function.variadic &&
				ocelot_type_list_equivalent(a->compound.function.parameters,
					b->compound.function.parameters) &&
				ocelot_type_equivalent(a->compound.function.return_type,
					b->compound.function.return_type);
		}
		break;
	case OC_TYPE_STRUCT:
	case OC_TYPE_UNION:
		if (a->compound.record_fields == NULL || a->compound.record_fields[0] == NULL)
		{
			free(a->compound.record_fields);
			a->compound.record_fields = ocelot_record_field_list_dup(b->compound.record_fields);
			equivalent = 1;
		}
		else if (b->compound.record_fields == NULL || b->compound.record_fields[0] == NULL)
		{
			equivalent = 1;
		}
		else
		{
			equivalent = ocelot_record_field_list_equivalent(a->compound.record_fields, b->compound.record_fields);
		}
		break;
	default:
		equivalent = 1;
		break;
	}
cleanup:
	return equivalent;
}

static int ocelot_symbols_put(ocelot_symbols *symbols, ocelot_symbol *symbol)
{
	if (symbol->name == NULL || symbol->name[0] == '\0')
	{
		return -1;
	}
	uint64_t hash;
	ocelot_symbol_chain **chain = ocelot_symbols_find_chain(symbols, symbol->name, &hash);
	if (*chain == NULL)
	{
		*chain = ocelot_symbol_chain_new(symbol, hash);
		if (*chain == NULL) return -1;
		(*chain)->next = NULL;
		symbols->entry_count++;
		if ((double) symbols->entry_count / symbols->bucket_count > OC_SYMBOL_TABLE_MAX_LOAD)
		{
			ocelot_symbols_resize(symbols, (symbols->bucket_count << 1));
		}
	}
	else
	{
		ocelot_symbol *old_symbol = (*chain)->symbol;
		if (ocelot_type_equivalent(old_symbol->type, symbol->type))
		{
			if (old_symbol->linkage == OC_SYMBOL_EXTERN)
			{
				old_symbol->linkage = symbol->linkage;
			}
			old_symbol->elaborated = old_symbol->elaborated || symbol->elaborated;
		}
		return 1;
	}
	return 0;
}

static ocelot_symbol *ocelot_parse_symbol_new(ocelot_symbol_class symbol_class, CXCursor cursor)
{
	CXString name = clang_getCursorSpelling(cursor);
	ocelot_symbol *symbol = ocelot_symbol_new(symbol_class, clang_getCString(name));
	clang_disposeString(name);
	if (symbol != NULL)
	{
		enum CX_StorageClass linkage = clang_Cursor_getStorageClass(cursor);
		if (linkage == 	CX_SC_Static)
		{
			symbol->linkage = OC_SYMBOL_PRIVATE;
		}
		else if (linkage == CX_SC_None)
		{
			symbol->linkage = OC_SYMBOL_PUBLIC;
		}
		else if (linkage == CX_SC_Extern)
		{
			symbol->linkage = OC_SYMBOL_EXTERN;
		}
	}
	return symbol;
}

static char *ocelot_parse_type_name(CXType type, int *elaborated)
{
	if (elaborated != NULL)
	{
		*elaborated = 0;
	}
	if (type.kind == CXType_Pointer || type.kind == CXType_ConstantArray || type.kind == CXType_IncompleteArray
		|| ocelot_type_is_atomic(ocelot_type_from_clang(type.kind)))
	{
		return NULL;
	}
	CXString cxSpelling = clang_getTypeSpelling(type);
	const char *cSpelling = clang_getCString(cxSpelling);
	if (strstr(cSpelling, "struct ") != NULL)
	{
		cSpelling = cSpelling + 7;
	}
	else if (strstr(cSpelling, "union ") != NULL)
	{
		cSpelling = cSpelling + 6;
	}
	else if (strstr(cSpelling, "enum ") != NULL)
	{
		cSpelling = cSpelling + 5;
	}
	if (elaborated)
	{
		*elaborated = clang_Type_getNamedType(type).kind != CXType_Invalid;
	}
	char *spelling = ocelot_strdup(cSpelling);
	clang_disposeString(cxSpelling);
	if (strstr(spelling, "(anonymous") != NULL)
	{
		free(spelling);
		spelling = NULL;
	}
	return spelling;
}

static ocelot_symbol *ocelot_cursor_to_symbol(CXCursor cursor, ocelot_symbols *symbols);

static ocelot_type *ocelot_parse_resolve_type(CXType type, ocelot_symbols *symbols)
{
	ocelot_type *resolved_type = NULL;
	ocelot_symbol *symbol = NULL;
	int indirection = 0;
	while (type.kind == CXType_Pointer || type.kind == CXType_IncompleteArray)
	{
		indirection++;
		if (type.kind == CXType_Pointer)
		{
			type = clang_getPointeeType(type);
		}
		else if (type.kind == CXType_IncompleteArray)
		{
			type = clang_getArrayElementType(type);
		}
	}
	if (indirection > 0)
	{
		resolved_type = ocelot_type_new(OC_TYPE_POINTER);
		if (resolved_type == NULL) goto cleanup;
		resolved_type->compound.pointer.indirection = indirection;
		resolved_type->compound.pointer.base_type = ocelot_parse_resolve_type(type, symbols);
		if (resolved_type->compound.pointer.base_type == NULL) goto cleanup;
	}
	else if (type.kind == CXType_ConstantArray)
	{
		resolved_type = ocelot_type_new(OC_TYPE_ARRAY);
		if (resolved_type == NULL) goto cleanup;
		resolved_type->compound.array.size = clang_getArraySize(type);
		type = clang_getArrayElementType(type);
		resolved_type->compound.array.base_type = ocelot_parse_resolve_type(type, symbols);
		if (resolved_type->compound.array.base_type == NULL) goto cleanup;
	}
	else if (type.kind == CXType_Record)
	{
		char *spelling = ocelot_parse_type_name(type, NULL);
		symbol = ocelot_symbols_get(symbols, spelling);
		free(spelling);
		if (symbol == NULL)
		{
			CXCursor cursor = clang_getTypeDeclaration(type);
			symbol = ocelot_cursor_to_symbol(cursor, symbols);
			if (symbol == NULL) goto cleanup;
			resolved_type = ocelot_type_dup(symbol->type);
			if (ocelot_symbols_put(symbols, symbol))
			{
				ocelot_symbol_delete(symbol);
			}
		}
		else
		{
			ocelot_type_class type_class = symbol->type->type_class;
			int correct_type = (type.kind == CXType_Record && (type_class == OC_TYPE_STRUCT || type_class == OC_TYPE_UNION));
			if (!correct_type) goto cleanup;
			resolved_type = ocelot_type_dup(symbol->type);
			free(resolved_type->name);
			resolved_type->name = ocelot_strdup(symbol->name);
		}
	}
	else if (type.kind == CXType_Enum)
	{
		char *spelling = ocelot_parse_type_name(type, NULL);
		symbol = ocelot_symbols_get(symbols, spelling);
		free(spelling);
		if (symbol == NULL)
		{
			CXCursor cursor = clang_getTypeDeclaration(type);
			symbol = ocelot_cursor_to_symbol(cursor, symbols);
			if (symbol == NULL) goto cleanup;
			resolved_type = ocelot_type_dup(symbol->type);
			if (ocelot_symbols_put(symbols, symbol))
			{
				ocelot_symbol_delete(symbol);
			}
		}
		else
		{
			ocelot_type_class type_class = symbol->type->type_class;
			int correct_type = (type.kind == CXType_Enum && (type_class == OC_TYPE_ENUM));
			if (!correct_type) goto cleanup;
			resolved_type = ocelot_type_dup(symbol->type);
			free(resolved_type->name);
			resolved_type->name = ocelot_strdup(symbol->name);
		}
	}
	else if (type.kind == CXType_FunctionProto)
	{
		resolved_type = ocelot_type_new(OC_TYPE_FUNCTION);
		if (resolved_type == NULL) goto cleanup;
		resolved_type->compound.function.parameters = NULL;
		resolved_type->compound.function.return_type = NULL;
		resolved_type->compound.function.variadic = clang_isFunctionTypeVariadic(type);
		unsigned argc = clang_getNumArgTypes(type);
		resolved_type->compound.function.parameters = (ocelot_type**) malloc(sizeof(ocelot_type*) * (argc + 1));
		if (resolved_type->compound.function.parameters == NULL) goto cleanup;
		unsigned i;
		for (i = 0; i < argc; i++)
		{
			CXType arg = clang_getArgType(type, i);
			ocelot_type *arg_type = ocelot_parse_resolve_type(arg, symbols);
			if (arg_type == NULL)
			{
				resolved_type->compound.function.parameters[i] = NULL;
				goto cleanup;
			}
			resolved_type->compound.function.parameters[i] = arg_type;
			if (resolved_type->compound.function.parameters[i] == NULL) goto cleanup;
		}
		resolved_type->compound.function.parameters[argc] = NULL;
		CXType result_type = clang_getResultType(type);
		resolved_type->compound.function.return_type = ocelot_parse_resolve_type(result_type, symbols);
		if (resolved_type->compound.function.return_type == NULL) goto cleanup;
		CXCursor cursor = clang_getTypeDeclaration(type);
		if (cursor.kind == CXCursor_FunctionDecl)
		{
			ocelot_symbol *symbol = ocelot_parse_symbol_new(OC_SYMBOL_FUNCTION, cursor);
			if (symbol != NULL)
			{
				symbol->type = ocelot_type_dup(resolved_type);
				if (symbol->type != NULL)
				{
					if (ocelot_symbols_put(symbols, symbol))
					{
						ocelot_symbol_delete(symbol);
					}
				}
				else
				{
					ocelot_symbol_delete(symbol);
				}
			}
		}
	}
	else if (type.kind == CXType_Typedef)
	{
		CXString cxString = clang_getTypedefName(type);
		CXCursor cursor = clang_getTypeDeclaration(type);
		type = clang_getTypedefDeclUnderlyingType(cursor);
		symbol = ocelot_symbols_get(symbols, clang_getCString(cxString));
		if (symbol == NULL)
		{
			symbol = ocelot_parse_symbol_new(OC_SYMBOL_TYPE, cursor);
			if (symbol != NULL)
			{
				free(symbol->name);
				symbol->name = ocelot_strdup(clang_getCString(cxString));
				symbol->type = ocelot_parse_resolve_type(type, symbols);
				if (!ocelot_type_is_atomic(symbol->type->type_class))
				{
					free(symbol->type->name);
					symbol->type->name = ocelot_parse_type_name(type, &symbol->elaborated);
				}
				resolved_type = ocelot_type_dup(symbol->type);
				if (ocelot_symbols_put(symbols, symbol))
				{
					ocelot_symbol_delete(symbol);
				}
			}
 		}
		else
		{
			resolved_type = ocelot_type_dup(symbol->type);
			if (resolved_type == NULL)
			{
				clang_disposeString(cxString);
				goto cleanup;
			}
			else if (!ocelot_type_is_atomic(resolved_type->type_class))
			{
				free(resolved_type->name);
				resolved_type->name = ocelot_strdup(clang_getCString(cxString));
			}
		}
		clang_disposeString(cxString);
	}
	else if (type.kind == CXType_Elaborated)
	{
		CXCursor cursor = clang_getTypeDeclaration(type);
		symbol = ocelot_parse_symbol_new(OC_SYMBOL_TYPE, cursor);
		type = clang_Type_getNamedType(type);
		symbol->type = ocelot_parse_resolve_type(type, symbols);
		symbol->elaborated = 1;
		resolved_type = ocelot_type_dup(symbol->type);
		if (ocelot_symbols_put(symbols, symbol))
		{
			ocelot_symbol_delete(symbol);
		}
	}
	else
	{
		resolved_type = ocelot_type_new(ocelot_type_from_clang(type.kind));
	}
	if (resolved_type->name != NULL && resolved_type->name[0] != '\0')
	{
		ocelot_clear_compound(resolved_type);
	}
	return resolved_type;
cleanup:
	ocelot_type_delete(resolved_type);
	return NULL;
}

typedef struct
{
	ocelot_symbols *table;
	ocelot_record_field **fields;
	ocelot_symbol *symbol;
	size_t i;
} ocelot_record_fields;

static enum CXChildVisitResult ocelot_parse_add_field(CXCursor cursor, CXCursor parent, CXClientData data)
{
	(void) parent;
	ocelot_record_field *field;
	ocelot_symbol *symbol = NULL;
	ocelot_record_fields *fields = (ocelot_record_fields*) data;
	CXType type = clang_getCursorType(cursor);
	CXString cxString;
	if (cursor.kind == CXCursor_FieldDecl)
	{
		cxString = clang_getCursorSpelling(cursor);
		field = ocelot_record_field_new(clang_getCString(cxString));
		clang_disposeString(cxString);
		if (fields->symbol != NULL)
		{
			symbol = fields->symbol;
			fields->symbol = NULL;
			field->type = ocelot_type_dup(symbol->type);
			free(field->type->name);
			field->type->name = ocelot_parse_type_name(type, NULL);
			fields->fields[fields->i++] = field;
			fields->fields[fields->i] = NULL;
		}
		else if (field != NULL)
		{
			field->type = ocelot_parse_resolve_type(type, fields->table);
			if (field->type->name == NULL)
			{
				field->type->name = ocelot_parse_type_name(type, NULL);
			}
			fields->fields[fields->i++] = field;
			fields->fields[fields->i] = NULL;
		}
		else
		{
			ocelot_record_field_delete(field);
		}
		return CXChildVisit_Continue;
	}
	else if (cursor.kind == CXCursor_StructDecl || cursor.kind == CXCursor_UnionDecl || cursor.kind == CXCursor_EnumDecl)
	{
		symbol = ocelot_cursor_to_symbol(cursor, fields->table);
		if (!ocelot_symbols_put(fields->table, symbol))
		{
			fields->symbol = symbol;
		}
		else
		{
			ocelot_symbol_delete(symbol);
		}
		return CXChildVisit_Continue;
	}
	return CXChildVisit_Break;
}

static enum CXChildVisitResult ocelot_parse_count_fields(CXCursor cursor, CXCursor parent, CXClientData data)
{
	(void) parent;
	if (cursor.kind == CXCursor_FieldDecl)
	{
		(*(unsigned*) data)++;
	}
	return CXChildVisit_Continue;
}

typedef struct
{
	ocelot_enum_field **fields;
	size_t i;
} ocelot_enum_fields;

static enum CXChildVisitResult ocelot_parse_add_enum_constant(CXCursor cursor, CXCursor parent, CXClientData data)
{
	(void) parent;
	ocelot_enum_field *field;
	ocelot_enum_fields *fields = (ocelot_enum_fields*) data;
	CXString cxString;
	if (cursor.kind == CXCursor_EnumConstantDecl)
	{
		cxString = clang_getCursorSpelling(cursor);
		field = ocelot_enum_field_new(clang_getCString(cxString), clang_getEnumConstantDeclValue(cursor));
		clang_disposeString(cxString);
		if (field != NULL)
		{
			fields->fields[fields->i++] = field;
			fields->fields[fields->i] = NULL;
		}
		else
		{
			return CXChildVisit_Break;
		}
	}
	return CXChildVisit_Continue;
}

static enum CXChildVisitResult ocelot_parse_count_enum_constants(CXCursor cursor, CXCursor parent, CXClientData data)
{
	(void) parent;
	if (cursor.kind == CXCursor_EnumConstantDecl)
	{
		(*(unsigned*) data)++;
	}
	return CXChildVisit_Continue;
}

static ocelot_symbol *ocelot_cursor_to_symbol(CXCursor cursor, ocelot_symbols *symbols)
{
	ocelot_symbol *symbol = NULL;
	enum CXCursorKind kind = cursor.kind;
	CXType type;
	unsigned field_count;
	CXType cursor_type = clang_getCursorType(cursor);
	CXCursor definition_cursor;
	CXString cxString;
	char *name;
	switch (kind)
	{
	case CXCursor_ParmDecl:
		symbol = ocelot_parse_symbol_new(-1, cursor);
		if (symbol == NULL) goto cleanup;
		symbol->type = ocelot_parse_resolve_type(cursor_type, symbols);
		break;
	case CXCursor_FieldDecl:
		symbol = ocelot_parse_symbol_new(-1, cursor);
		if (symbol == NULL) goto cleanup;
		symbol->type = ocelot_parse_resolve_type(cursor_type, symbols);
		break;
	case CXCursor_StructDecl:
	case CXCursor_UnionDecl:
		definition_cursor = clang_getCursorDefinition(cursor);
		if (definition_cursor.kind < CXCursor_FirstInvalid && definition_cursor.kind > CXCursor_LastInvalid)
		{
			cursor = definition_cursor;
		}
		symbol = ocelot_parse_symbol_new(OC_SYMBOL_TYPE, cursor);
		if (symbol == NULL) goto cleanup;
		free(symbol->name);
		symbol->name = ocelot_parse_type_name(clang_getCursorType(cursor), &symbol->elaborated);
		symbol->type = ocelot_type_new(kind == CXCursor_StructDecl ? OC_TYPE_STRUCT : OC_TYPE_UNION);
		if (symbol->type == NULL) goto cleanup;
		free(symbol->type->name);
		symbol->type->name = ocelot_strdup(symbol->name);
		if (symbol->type->name == NULL && symbol->name != NULL) goto cleanup;
		ocelot_symbol *declaration = ocelot_symbol_dup(symbol);
		declaration->linkage = OC_SYMBOL_EXTERN;
		if (ocelot_symbols_put(symbols, declaration))
		{
			ocelot_symbol_delete(declaration);
		}
		field_count = 0;
		clang_visitChildren(cursor, ocelot_parse_count_fields, &field_count);
		ocelot_record_fields record_fields;
		record_fields.table = symbols;
		record_fields.fields = (ocelot_record_field**) malloc(sizeof(ocelot_record_field*) * (field_count + 1));
		if (kind == CXCursor_StructDecl || kind == CXCursor_UnionDecl)
		{
			symbol->type->compound.record_fields = record_fields.fields;
		}
		if (record_fields.fields == NULL) goto cleanup;
		record_fields.fields[0] = NULL;
		record_fields.i = 0;
		record_fields.symbol = NULL;
		if (field_count > 0)
		{
			clang_visitChildren(cursor, ocelot_parse_add_field, &record_fields);
		}
		if (record_fields.fields[0] == NULL)
		{
			symbol->linkage = OC_SYMBOL_EXTERN;
		}
		break;
	case CXCursor_EnumDecl:
		symbol = ocelot_parse_symbol_new(OC_SYMBOL_TYPE, cursor);
		if (symbol == NULL) goto cleanup;
		free(symbol->name);
		symbol->name = ocelot_parse_type_name(clang_getCursorType(cursor), &symbol->elaborated);
		symbol->type = ocelot_type_new(OC_TYPE_ENUM);
		if (symbol->type == NULL) goto cleanup;
		symbol->type->name = ocelot_strdup(symbol->name);
		field_count = 0;
		clang_visitChildren(cursor, ocelot_parse_count_enum_constants, &field_count);
		ocelot_enum_fields enum_fields;
		enum_fields.fields = (ocelot_enum_field**) malloc(sizeof(ocelot_enum_field*) * (field_count + 1));
		symbol->type->compound.enum_fields = enum_fields.fields;
		if (enum_fields.fields == NULL) goto cleanup;
		enum_fields.fields[0] = NULL;
		enum_fields.i = 0;
		clang_visitChildren(cursor, ocelot_parse_add_enum_constant, &enum_fields);
		break;
	case CXCursor_FunctionDecl:
		definition_cursor = clang_getCursorDefinition(cursor);
		if (definition_cursor.kind < CXCursor_FirstInvalid && definition_cursor.kind > CXCursor_LastInvalid)
		{
			cursor = definition_cursor;
		}
		cursor_type = clang_getCursorType(cursor);
		symbol = ocelot_parse_symbol_new(OC_SYMBOL_FUNCTION, cursor);
		if (symbol == NULL) goto cleanup;
		symbol->type = ocelot_parse_resolve_type(cursor_type, symbols);
		if (symbol->type == NULL) goto cleanup;
		break;
	case CXCursor_VarDecl:
		symbol = ocelot_parse_symbol_new(OC_SYMBOL_VARIABLE, cursor);
		if (symbol == NULL) goto cleanup;
		symbol->type = ocelot_parse_resolve_type(clang_getCursorType(cursor), symbols);
		if (symbol->type == NULL) goto cleanup;
		break;
	case CXCursor_TypedefDecl:
		type = clang_getTypedefDeclUnderlyingType(cursor);
		type = clang_getCanonicalType(type);
		if (type.kind == CXType_Elaborated)
		{
			CXCursor cursor = clang_getTypeDeclaration(type);
			symbol = ocelot_parse_symbol_new(OC_SYMBOL_TYPE, cursor);
			free(symbol->name);
			cxString = clang_getTypedefName(cursor_type);
			symbol->name = ocelot_strdup(clang_getCString(cxString));
			clang_disposeString(cxString);
			type = clang_Type_getNamedType(type);
			symbol->type = ocelot_parse_resolve_type(type, symbols);
			if (symbol->type != NULL)
			{
				free(symbol->type->name);
				symbol->type->name = ocelot_parse_type_name(type, &symbol->elaborated);
			}
		}
		else if (type.kind == CXType_Typedef)
		{
			name = ocelot_parse_type_name(type, NULL);
			symbol = ocelot_symbols_get(symbols, name);
			free(name);
			if (symbol != NULL)
			{
				free(symbol->type->name);
				symbol->type->name = ocelot_parse_type_name(type, &symbol->elaborated);
			}
		}
		else
		{
			symbol = ocelot_parse_symbol_new(OC_SYMBOL_TYPE, cursor);
			if (symbol == NULL) goto cleanup;
			symbol->type = ocelot_parse_resolve_type(type, symbols);
			if (symbol->type != NULL)
			{
				free(symbol->type->name);
				symbol->type->name = ocelot_parse_type_name(type, &symbol->elaborated);
			}
		}
		break;
	default:
		break;
	}
	return symbol;
cleanup:
	ocelot_symbol_delete(symbol);
	return NULL;
}

static enum CXChildVisitResult ocelot_collect_symbols(CXCursor cursor, CXCursor parent, CXClientData data)
{
	(void) parent;
	ocelot_symbols *symbols = (ocelot_symbols*) data;
	ocelot_symbol *symbol = ocelot_cursor_to_symbol(cursor, symbols);
	if (symbol != NULL && symbol->name != NULL && symbol->name[0] != '\0')
	{
		if (ocelot_symbols_put(symbols, symbol))
		{
			ocelot_symbol_delete(symbol);
		}
	}
	else
	{
		ocelot_symbol_delete(symbol);
	}
	return CXChildVisit_Continue;
}

ocelot_symbols *ocelot_parse(const char *path, char **include_dirs)
{
	ocelot_symbols *symbols = NULL;
	char *full_path = ocelot_find_file(path, include_dirs);
	if (full_path != NULL)
	{
		int argc, i;
		char **include;
		for (argc = 0, include = include_dirs; *include != NULL; argc += 2, include++);
		const char **argv = NULL;
		if (argc > 0)
		{
			argv = (const char**) malloc(sizeof(char*) * argc);
			if (argv == NULL) goto cleanup;
		}
		for (i = 0; i < argc; i += 2)
		{
			argv[i] = "-I";
			argv[i + 1] = include_dirs[i >> 1];
		}
		symbols = ocelot_symbols_new();
		if (symbols == NULL) goto cleanup;
		CXIndex idx = clang_createIndex(0, 1);
		CXTranslationUnit tu = clang_parseTranslationUnit(idx, full_path, argv, argc, NULL, 0, 0);
		CXCursor cursor = clang_getTranslationUnitCursor(tu);
		clang_visitChildren(cursor, ocelot_collect_symbols, symbols);
		clang_disposeTranslationUnit(tu);
		clang_disposeIndex(idx);
cleanup:
		free(argv);
		free(full_path);
	}
	return symbols;
}

char **ocelot_split_include_dirs(const char *include_dirs)
{
	unsigned count = 0, capacity = 16;
	unsigned start, end;
	char **split = (char**) malloc(sizeof(char*) * capacity);
	if (split == NULL) goto end;
	split[0] = NULL;
	for (start = 0; include_dirs[start] != '\0'; start = end)
	{
		while (include_dirs[start] == ':')
		{
			start++;
		}
		end = start;
		while (include_dirs[end] != ':' && include_dirs[end] != '\0')
		{
			end++;
		}
		if (include_dirs[start] != '\0')
		{
			if (count + 1 >= capacity)
			{
				capacity <<= 1;
				char **new_split = (char**) realloc(split, sizeof(char*) * capacity);
				if (new_split == NULL) goto end;
				split = new_split;
			}
			unsigned len = end - start;
			char *dir = (char*) malloc(len + 1);
			if (dir == NULL) goto end;
			memcpy(dir, include_dirs + start, len);
			dir[len] = '\0';
			split[count++] = dir;
			split[count] = NULL;
		}
	}
end:
	return split;
}

void ocelot_free_include_dirs(char **include_dirs)
{
	if (include_dirs != NULL)
	{
		char **dir;
		for (dir = include_dirs; *dir != NULL; dir++)
		{
			free(*dir);
		}
		free(include_dirs);
	}
}

ocelot_symbol *ocelot_symbols_get(const ocelot_symbols *symbols, const char *name)
{
	ocelot_symbol *symbol = NULL;
	if (name == NULL) goto cleanup;
	ocelot_symbol_chain **chain = ocelot_symbols_find_chain(symbols, name, NULL);
	if (*chain == NULL) goto cleanup;
	symbol = (*chain)->symbol;
cleanup:
	return symbol;
}

static size_t ocelot_symbols_count(const ocelot_symbols *symbols)
{
	size_t symbol_count = 0;
	uint32_t i;
	for (i = 0; i < symbols->bucket_count; i++)
	{
		ocelot_symbol_chain *chain;
		for (chain = symbols->buckets[i]; chain != NULL; chain = chain->next)
		{
			symbol_count++;
		}
	}
	return symbol_count;
}

static int compare_symbols(const void *a, const void *b)
{
	return strcmp((*(ocelot_symbol**) a)->name, (*(ocelot_symbol**) b)->name);
}

ocelot_symbol **ocelot_symbols_get_all(const ocelot_symbols *symbols)
{
	size_t symbol_count = ocelot_symbols_count(symbols);
	ocelot_symbol **all_symbols = (ocelot_symbol**) malloc(sizeof(ocelot_symbol*) * (symbol_count + 1));
	uint32_t i, j;
	for (i = 0, j = 0; i < symbols->bucket_count && j < symbol_count; i++)
	{
		ocelot_symbol_chain *chain;
		for (chain = symbols->buckets[i]; chain != NULL; chain = chain->next)
		{
			all_symbols[j++] = chain->symbol;
		}
	}
	all_symbols[symbol_count] = NULL;
	qsort(all_symbols, symbol_count, sizeof(ocelot_symbol*), &compare_symbols);
	return all_symbols;
}

#ifdef OCELOT_ENABLE_JSON

#include "cJSON/cJSON.c"

static const char *ocelot_json_serialize_symbol_class(ocelot_symbol_class symbol_class)
{
	switch (symbol_class)
	{
	case OC_SYMBOL_FUNCTION:
		return "function";
	case OC_SYMBOL_TYPE:
		return "type";
	case OC_SYMBOL_VARIABLE:
		return "variable";
	default:
		return NULL;
	}
}

static const char *ocelot_json_serialize_symbol_linkage(ocelot_symbol_linkage symbol_linkage)
{
	switch (symbol_linkage)
	{
	case OC_SYMBOL_PRIVATE:
		return "private";
	case OC_SYMBOL_PUBLIC:
		return "public";
	case OC_SYMBOL_EXTERN:
		return "extern";
	default:
		return NULL;
	}
}

static const char *ocelot_json_serialize_type_class(ocelot_type_class type_class)
{
	switch (type_class)
	{
	case OC_TYPE_VOID:
		return "void";
	case OC_TYPE_POINTER:
		return "pointer";
	case OC_TYPE_ARRAY:
		return "array";
	case OC_TYPE_CHAR:
		return "char";
	case OC_TYPE_UCHAR:
		return "unsigned char";
	case OC_TYPE_SHORT:
		return "short";
	case OC_TYPE_USHORT:
		return "unsigned short";
	case OC_TYPE_INT:
		return "int";
	case OC_TYPE_UINT:
		return "unsigned int";
	case OC_TYPE_LONG:
		return "long";
	case OC_TYPE_ULONG:
		return "unsigned long";
	case OC_TYPE_LLONG:
		return "long long";
	case OC_TYPE_ULLONG:
		return "unsigned long long";
	case OC_TYPE_FLOAT:
		return "float";
	case OC_TYPE_DOUBLE:
		return "double";
	case OC_TYPE_LDOUBLE:
		return "long double";
	case OC_TYPE_BOOL:
		return "bool";
	case OC_TYPE_FUNCTION:
		return "function";
	case OC_TYPE_STRUCT:
		return "struct";
	case OC_TYPE_UNION:
		return "union";
	case OC_TYPE_ENUM:
		return "enum";
	default:
		return NULL;
	}
}

static cJSON *ocelot_json_serialize_type(const ocelot_type *type);

static cJSON *ocelot_json_serialize_type_list(ocelot_type **list)
{
	cJSON *json = cJSON_CreateArray();
	if (json == NULL) goto end;
	ocelot_type **itr;
	for (itr = list; *itr != NULL; itr++)
	{
		cJSON *item = ocelot_json_serialize_type(*itr);
		if (item == NULL) goto end;
		cJSON_AddItemToArray(json, item);
	}
end:
	return json;
}

static cJSON *ocelot_json_serialize_record_fields(ocelot_record_field **record_fields)
{
	cJSON *json = cJSON_CreateArray();
	if (json == NULL) goto end;
	ocelot_record_field **itr;
	for (itr = record_fields; *itr != NULL; itr++)
	{
		cJSON *item = cJSON_CreateObject();
		if (item == NULL) goto end;
		if (cJSON_AddStringToObject(item, "name", (*itr)->name) == NULL) goto end;
		if (!cJSON_AddItemToObject(item, "type", ocelot_json_serialize_type((*itr)->type))) goto end;
		cJSON_AddItemToArray(json, item);
	}
end:
	return json;
}

static cJSON *ocelot_json_serialize_enum_fields(ocelot_enum_field **enum_fields)
{
	cJSON *json = cJSON_CreateArray();
	if (json == NULL) goto end;
	ocelot_enum_field **itr;
	for (itr = enum_fields; *itr != NULL; itr++)
	{
		cJSON *item = cJSON_CreateObject();
		if (item == NULL) goto end;
		if (cJSON_AddStringToObject(item, "name", (*itr)->name) == NULL) goto end;
		if (cJSON_AddNumberToObject(item, "value", (*itr)->value) == NULL) goto end;
		cJSON_AddItemToArray(json, item);
	}
end:
	return json;
}

static cJSON *ocelot_json_serialize_type(const ocelot_type *type)
{
	cJSON *json = cJSON_CreateObject();
	if (json == NULL) goto end;
	if (type->name != NULL && cJSON_AddStringToObject(json, "name", type->name) == NULL) goto end;
	if (cJSON_AddStringToObject(json, "type_class", ocelot_json_serialize_type_class(type->type_class)) == NULL) goto end;
	switch (type->type_class)
	{
	case OC_TYPE_POINTER:
		if (type->compound.pointer.base_type == NULL) break;
		if (cJSON_AddNumberToObject(json, "indirection", (double) type->compound.pointer.indirection) == NULL) goto end;
		if (!cJSON_AddItemToObject(json, "base_type", ocelot_json_serialize_type(type->compound.pointer.base_type))) goto end;
		break;
	case OC_TYPE_ARRAY:
		if (type->compound.array.base_type == NULL) break;
		if (cJSON_AddNumberToObject(json, "size", (double) type->compound.array.size) == NULL) goto end;
		if (!cJSON_AddItemToObject(json, "base_type", ocelot_json_serialize_type(type->compound.array.base_type))) goto end;
		break;
	case OC_TYPE_FUNCTION:
		if (type->compound.function.parameters == NULL) break;
		if (!cJSON_AddItemToObject(json, "parameters", ocelot_json_serialize_type_list(type->compound.function.parameters))) goto end;
		if (!cJSON_AddItemToObject(json, "return_type", ocelot_json_serialize_type(type->compound.function.return_type))) goto end;
		if (cJSON_AddBoolToObject(json, "variadic", type->compound.function.variadic) == NULL) goto end;
		break;
	case OC_TYPE_STRUCT:
	case OC_TYPE_UNION:
		if (type->compound.record_fields == NULL) break;
		if (!cJSON_AddItemToObject(json, "record_fields", ocelot_json_serialize_record_fields(type->compound.record_fields))) goto end;
		break;
	case OC_TYPE_ENUM:
		if (type->compound.enum_fields == NULL) break;
		if (!cJSON_AddItemToObject(json, "enum_fields", ocelot_json_serialize_enum_fields(type->compound.enum_fields))) goto end;
		break;
	default:
		break;
	}
end:
	return json;
}

char *ocelot_json_serialize(const ocelot_symbols *symbols)
{
	ocelot_symbol **all_symbols = NULL;
	char *serialized = NULL;
	cJSON *json = cJSON_CreateArray();
	if (json == NULL) goto end;
	all_symbols = ocelot_symbols_get_all(symbols);
	if (all_symbols == NULL) goto end;
	ocelot_symbol **itr;
	for (itr = all_symbols; *itr != NULL; itr++)
	{
		ocelot_type_class type_class = (*itr)->type->type_class;
		cJSON *symbol = cJSON_CreateObject();
		if (cJSON_AddStringToObject(symbol, "name", (*itr)->name) == NULL) goto end;
		if (cJSON_AddStringToObject(symbol, "symbol_class", ocelot_json_serialize_symbol_class((*itr)->symbol_class)) == NULL) goto end;
		if (cJSON_AddStringToObject(symbol, "linkage", ocelot_json_serialize_symbol_linkage((*itr)->linkage)) == NULL) goto end;
		if ((type_class == OC_TYPE_STRUCT || type_class == OC_TYPE_UNION || type_class == OC_TYPE_ENUM)
				&& cJSON_AddBoolToObject(symbol, "elaborated", (*itr)->elaborated) == NULL) goto end;
		if (!cJSON_AddItemToObject(symbol, "type", ocelot_json_serialize_type((*itr)->type))) goto end;
		cJSON_AddItemToArray(json, symbol);
	}
	serialized = cJSON_Print(json);
end:
	free(all_symbols);
	cJSON_Delete(json);
	return serialized;
}

static ocelot_symbol_class ocelot_json_parse_symbol_class(const char *symbol_class)
{
	if (!strcmp(symbol_class, "function"))
	{
		return OC_SYMBOL_FUNCTION;
	}
	else if (!strcmp(symbol_class, "type"))
	{
		return OC_SYMBOL_TYPE;
	}
	else if (!strcmp(symbol_class, "variable"))
	{
		return OC_SYMBOL_VARIABLE;
	}
	else
	{
		return -1;
	}
}

static ocelot_symbol_linkage ocelot_json_parse_symbol_linkage(const char *linkage)
{
	if (!strcmp(linkage, "private"))
	{
		return OC_SYMBOL_PRIVATE;
	}
	else if (!strcmp(linkage, "public"))
	{
		return OC_SYMBOL_PUBLIC;
	}
	else if (!strcmp(linkage, "extern"))
	{
		return OC_SYMBOL_EXTERN;
	}
	else
	{
		return -1;
	}
}

static int ocelot_json_parse_bool(const cJSON *json)
{
	return json != NULL && json->type == cJSON_True;
}

static ocelot_type *ocelot_json_parse_type(const cJSON *json);

static ocelot_type_class ocelot_json_parse_type_class(const char *type_class)
{
	if (!strcmp(type_class, "void"))
	{
		return OC_TYPE_VOID;
	}
	else if (!strcmp(type_class, "pointer"))
	{
		return OC_TYPE_POINTER;
	}
	else if (!strcmp(type_class, "array"))
	{
		return OC_TYPE_ARRAY;
	}
	else if (!strcmp(type_class, "char"))
	{
		return OC_TYPE_CHAR;
	}
	else if (!strcmp(type_class, "unsigned char"))
	{
		return OC_TYPE_UCHAR;
	}
	else if (!strcmp(type_class, "short"))
	{
		return OC_TYPE_SHORT;
	}
	else if (!strcmp(type_class, "unsigned short"))
	{
		return OC_TYPE_USHORT;
	}
	else if (!strcmp(type_class, "int"))
	{
		return OC_TYPE_INT;
	}
	else if (!strcmp(type_class, "unsigned int"))
	{
		return OC_TYPE_UINT;
	}
	else if (!strcmp(type_class, "long"))
	{
		return OC_TYPE_LONG;
	}
	else if (!strcmp(type_class, "unsigned long"))
	{
		return OC_TYPE_ULONG;
	}
	else if (!strcmp(type_class, "long long"))
	{
		return OC_TYPE_LLONG;
	}
	else if (!strcmp(type_class, "unsigned long long"))
	{
		return OC_TYPE_ULLONG;
	}
	else if (!strcmp(type_class, "float"))
	{
		return OC_TYPE_FLOAT;
	}
	else if (!strcmp(type_class, "double"))
	{
		return OC_TYPE_DOUBLE;
	}
	else if (!strcmp(type_class, "ldouble"))
	{
		return OC_TYPE_LDOUBLE;
	}
	else if (!strcmp(type_class, "bool"))
	{
		return OC_TYPE_BOOL;
	}
	else if (!strcmp(type_class, "function"))
	{
		return OC_TYPE_FUNCTION;
	}
	else if (!strcmp(type_class, "struct"))
	{
		return OC_TYPE_STRUCT;
	}
	else if (!strcmp(type_class, "union"))
	{
		return OC_TYPE_UNION;
	}
	else if (!strcmp(type_class, "enum"))
	{
		return OC_TYPE_ENUM;
	}
	else
	{
		return -1;
	}
}

static ocelot_type **ocelot_json_parse_type_list(const cJSON *json)
{
	if (json == NULL) return NULL;

	int size = cJSON_GetArraySize(json);
	ocelot_type **list = (ocelot_type**) malloc(sizeof(ocelot_type*) * (size + 1));
	if (list == NULL) goto cleanup;
	list[0] = NULL;
	int i;
	for (i = 0; i < size; i++)
	{
		cJSON *type_json = cJSON_GetArrayItem(json, i);
		if (type_json == NULL) goto cleanup;
		list[i] = ocelot_json_parse_type(type_json);
		if (list[i] == NULL) goto cleanup;
		list[i + 1] = NULL;
	}
	return list;
cleanup:
	ocelot_type_list_delete(list);
	return NULL;
}

static ocelot_record_field *ocelot_json_parse_record_field(const cJSON *json)
{
	if (json == NULL) return NULL;

	cJSON *name_json = cJSON_GetObjectItemCaseSensitive(json, "name");
	cJSON *type_json = cJSON_GetObjectItemCaseSensitive(json, "type");

	char *name = cJSON_GetStringValue(name_json);
	ocelot_type *type = ocelot_json_parse_type(type_json);

	ocelot_record_field *field = NULL;
	if (name != NULL && type != NULL)
	{
		field = ocelot_record_field_new(name);
		if (field != NULL)
		{
			field->type = type;
		}
		else
		{
			ocelot_type_delete(type);
		}
	}
	return field;
}

static ocelot_record_field **ocelot_json_parse_record_fields(const cJSON *json)
{
	if (json == NULL) return NULL;

	int size = cJSON_GetArraySize(json);
	ocelot_record_field **list = (ocelot_record_field**) malloc(sizeof(ocelot_record_field*) * (size + 1));
	if (list == NULL) goto cleanup;
	list[0] = NULL;
	int i;
	for (i = 0; i < size; i++)
	{
		cJSON *field_json = cJSON_GetArrayItem(json, i);
		if (field_json == NULL) goto cleanup;
		list[i] = ocelot_json_parse_record_field(field_json);
		if (list[i] == NULL) goto cleanup;
		list[i + 1] = NULL;
	}
	return list;
cleanup:
	ocelot_record_field_list_delete(list);
	return NULL;
}

static ocelot_enum_field *ocelot_json_parse_enum_field(const cJSON *json)
{
	if (json == NULL) return NULL;

	cJSON *name_json = cJSON_GetObjectItemCaseSensitive(json, "name");
	cJSON *value_json = cJSON_GetObjectItemCaseSensitive(json, "value");

	char *name = cJSON_GetStringValue(name_json);
	double number = cJSON_GetNumberValue(value_json);

	ocelot_enum_field *field = NULL;
	if (name != NULL && !isnan(number))
	{
		field = ocelot_enum_field_new(name, (long long) number);
	}
	return field;
}

static ocelot_enum_field **ocelot_json_parse_enum_fields(const cJSON *json)
{
	if (json == NULL) return NULL;

	int size = cJSON_GetArraySize(json);
	ocelot_enum_field **list = (ocelot_enum_field**) malloc(sizeof(ocelot_enum_field*) * (size + 1));
	if (list == NULL) goto cleanup;
	list[0] = NULL;
	int i;
	for (i = 0; i < size; i++)
	{
		cJSON *field_json = cJSON_GetArrayItem(json, i);
		if (field_json == NULL) goto cleanup;
		list[i] = ocelot_json_parse_enum_field(field_json);
		if (list[i] == NULL) goto cleanup;
		list[i + 1] = NULL;
	}
	return list;
cleanup:
	ocelot_enum_field_list_delete(list);
	return NULL;
}

static ocelot_type *ocelot_json_parse_type(const cJSON *json)
{
	if (json == NULL) return NULL;

	cJSON *name_json = cJSON_GetObjectItemCaseSensitive(json, "name");
	cJSON *type_class_json = cJSON_GetObjectItemCaseSensitive(json, "type_class");

	char *name = cJSON_GetStringValue(name_json);
	ocelot_type_class type_class = ocelot_json_parse_type_class(cJSON_GetStringValue(type_class_json));

	ocelot_type *type = NULL;
	if (type_class >= 0)
	{
		type = ocelot_type_new(type_class);
		type->name = ocelot_strdup(name);

		cJSON *field;
		double number;
		switch (type_class)
		{
		case OC_TYPE_POINTER:
			field = cJSON_GetObjectItemCaseSensitive(json, "indirection");
			number = cJSON_GetNumberValue(field);
			type->compound.pointer.indirection = (int) number;
			field = cJSON_GetObjectItemCaseSensitive(json, "base_type");
			type->compound.pointer.base_type = ocelot_json_parse_type(field);
			break;
		case OC_TYPE_ARRAY:
			field = cJSON_GetObjectItemCaseSensitive(json, "size");
			number = cJSON_GetNumberValue(field);
			type->compound.array.size = (int) number;
			field = cJSON_GetObjectItemCaseSensitive(json, "base_type");
			type->compound.array.base_type = ocelot_json_parse_type(field);
			break;
		case OC_TYPE_FUNCTION:
			field = cJSON_GetObjectItemCaseSensitive(json, "parameters");
			type->compound.function.parameters = ocelot_json_parse_type_list(field);
			field = cJSON_GetObjectItemCaseSensitive(json, "return_type");
			type->compound.function.return_type = ocelot_json_parse_type(field);
			field = cJSON_GetObjectItemCaseSensitive(json, "variadic");
			type->compound.function.variadic = ocelot_json_parse_bool(field);
			break;
		case OC_TYPE_STRUCT:
		case OC_TYPE_UNION:
			field = cJSON_GetObjectItemCaseSensitive(json, "record_fields");
			type->compound.record_fields = ocelot_json_parse_record_fields(field);
			break;
		case OC_TYPE_ENUM:
			field = cJSON_GetObjectItemCaseSensitive(json, "enum_fields");
			type->compound.enum_fields = ocelot_json_parse_enum_fields(field);
			break;
		default:
			break;
		}
	}
	return type;
}

ocelot_symbol *ocelot_json_parse_symbol(const cJSON *json)
{
	if (json == NULL) return NULL;

	cJSON *name_json = cJSON_GetObjectItemCaseSensitive(json, "name");
	cJSON *symbol_class_json = cJSON_GetObjectItemCaseSensitive(json, "symbol_class");
	cJSON *linkage_json = cJSON_GetObjectItemCaseSensitive(json, "linkage");
	cJSON *elaborated_json = cJSON_GetObjectItemCaseSensitive(json, "elaborated");
	cJSON *type_json = cJSON_GetObjectItemCaseSensitive(json, "type");

	char *name = cJSON_GetStringValue(name_json);
	ocelot_symbol_class symbol_class = ocelot_json_parse_symbol_class(cJSON_GetStringValue(symbol_class_json));
	ocelot_symbol_linkage linkage = ocelot_json_parse_symbol_linkage(cJSON_GetStringValue(linkage_json));
	int elaborated = ocelot_json_parse_bool(elaborated_json);
	ocelot_type *type = ocelot_json_parse_type(type_json);

	ocelot_symbol *symbol = NULL;
	if (name != NULL && symbol_class >= 0 && linkage >= 0 && type != NULL)
	{
		symbol = ocelot_symbol_new(symbol_class, name);
		symbol->linkage = linkage;
		symbol->elaborated = elaborated;
		symbol->type = type;
	}
	return symbol;
}

ocelot_symbols *ocelot_json_parse(const char *json)
{
	cJSON *parse = NULL;
	const cJSON *symbol_json;
	ocelot_symbol *symbol;
	ocelot_symbols *symbols = ocelot_symbols_new();
	if (symbols == NULL) goto cleanup;
	parse = cJSON_Parse(json);
	if (parse == NULL) goto cleanup;
	cJSON_ArrayForEach(symbol_json, parse)
	{
		symbol = ocelot_json_parse_symbol(symbol_json);
		if (symbol != NULL)
		{
			if (ocelot_symbols_put(symbols, symbol))
			{
				ocelot_symbol_delete(symbol);
			}
		}
	}
cleanup:
	cJSON_Delete(parse);
	return symbols;
}

#else

char *ocelot_json_serialize(const ocelot_symbols *symbols)
{
	(void) symbols;
	return NULL;
}

ocelot_symbols *ocelot_json_parse(const char *json)
{
	(void) json;
	return NULL;
}

#endif /* OCELOT_ENABLE_JSON */
