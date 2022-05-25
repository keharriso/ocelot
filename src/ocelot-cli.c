#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ocelot.h"

int main(int argc, char *argv[])
{
	int ret = 0;
	ocelot_symbols *symbols = NULL;
	const char *header = NULL;
	char **include_dirs = (char**) malloc(sizeof(char*) * (argc + 1));
	if (include_dirs == NULL)
	{
		fprintf(stderr, "error: malloc failed\n");
		ret = -1;
		goto cleanup;
	}
	char **include_dir = include_dirs;
	*include_dir = NULL;
	int i;
	if (argc == 1)
	{
		printf("ocelot [-I<dir> ...] <file>\n");
		goto cleanup;
	}
	else for (i = 1; i < argc; i++)
	{
		size_t arglen = strlen(argv[i]);
		if (argv[i][0] == '-')
		{
			if (argv[i][1] == 'I')
			{
				*include_dir = (char*) malloc(arglen);
				if (*include_dir == NULL)
				{
					fprintf(stderr, "error: malloc failed\n");
					ret = -1;
					goto cleanup;
				}
				strncpy(*(include_dir++), argv[i] + 2, arglen - 1);
				*include_dir = NULL;
			}
		}
		else if (header == NULL)
		{
			header = argv[i];
		}
		else
		{
			fprintf(stderr, "error: more than one target file specified\n");
			ret = -2;
			goto cleanup;
		}
	}
	symbols = ocelot_parse(header, include_dirs);
	if (symbols == NULL)
	{
		fprintf(stderr, "error: parse failed\n");
		ret = -3;
		goto cleanup;
	}
	char *json = ocelot_json_serialize(symbols);
	if (json == NULL)
	{
		fprintf(stderr, "error: serialization failed\n");
		ret = -4;
		goto cleanup;
	}
	puts(json);
	free(json);
cleanup:
	ocelot_symbols_delete(symbols);
	ocelot_free_include_dirs(include_dirs);
	return ret;
}
