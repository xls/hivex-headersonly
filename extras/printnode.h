#ifndef __HIVEX_PRINTNODES_H__
#define __HIVEX_PRINTNODES_H__

#ifndef HIVEX_H_
#include "hivex.h" /* or else make sure hivex.h is included before this tools */
#endif

static inline void tabify(int n)
{
	for (int i = 0; i < n; i++)
		putchar('\t');
}


void printnode(hive_h* hive, hive_node_h node, bool hexDump = true /* enable hexdump */)
{

	static int tabs = 0;
	int i = 0;
	int s = 0;
	int c = 0;
	if (node == 0) return;
	char* name = hivex_node_name(hive, node);
	tabify(tabs);
	printf("\\%s\n", name);
	tabs++;
	hivex_free(name);

	hive_value_h* values = hivex_node_values(hive, node);
	if (values != nullptr)
	{
		for (i = 0; values[i] != 0; ++i)
		{
			hive_value_h value = values[i];
			char* kname = hivex_value_key(hive, value);
			const char* display_key = kname;
			hive_type type;
			size_t vlen;
			hivex_value_type(hive, value, &type, &vlen);
			tabify(tabs);

			if (*display_key == 0)
				display_key = "(Default)";
			char* str = 0;
			hivex_free(kname);

			switch (type)
			{
			case hive_t_REG_SZ:
				str = hivex_value_string(hive, value);
				if (str != nullptr && *str != 0)
				{
					printf("[REG_SZ size:%zd]: \"%s\"\n", vlen, str);
				}
				else
				{
					printf("[REG_SZ]: (value not set)\n");
				}
				if (str != nullptr)
				{
					hivex_free(str);
					str = 0;
				}
				break;
			case hive_t_REG_NONE:
				printf("[REG_NONE]\n");
				break;
			case hive_t_REG_EXPAND_SZ:
				str = hivex_value_string(hive, value);
				if (str != nullptr && *str != 0)
				{
					printf("[REG_EXPAND_SZ size:%zd]: \"%s\"\n", vlen, str);
				}
				else
				{
					printf("REG_EXPAND_SZ: (value not set)\n");
				}
				if (str != nullptr)
				{
					hivex_free(str);
					str = 0;
				}
				hivex_free(str);
				str = 0;
				break;
			case hive_t_REG_DWORD:
				printf("[REG_DWORD(le) size:%zd]: 0x%x\n", vlen, hivex_value_dword(hive, value));
				break;
			case hive_t_REG_DWORD_BIG_ENDIAN:
				printf("[REG_DWORD(be) size:%zd]: 0x%x\n", vlen, hivex_value_dword(hive, value));
				break;
			case hive_t_REG_LINK:
				printf("[REG_LINK]\n");
				break;
			case hive_t_REG_MULTI_SZ:
			{
				char** strings = hivex_value_multiple_strings(hive, value);
				if (strings != nullptr)
				{
					printf("[REG_MULTI_SZ size:%zd]: {\n", vlen);
					for (s = 0; strings[s] != 0; ++s)
					{
						char* str = strings[s];
						tabify(tabs + 1);
						printf("\"%s\"%c\n", str, strings[s + 1] != 0 ? ',' : ' ');
					}
					tabify(tabs);
					printf("}\n");
					hivex_free_strings(strings);
				}
				strings = NULL;
			}
			break;
			case hive_t_REG_RESOURCE_LIST:
				printf("[resource]\n");
				break;
			case hive_t_REG_BINARY:
			{
				hive_type t2;
				size_t len;
				char* bin = hivex_value_value(hive, value, &t2, &len);

				printf("[REG_BINARY size:%zd]:", vlen);
				if (hexDump)
				{
					// hexdump
					if (bin != nullptr)
					{
						for (size_t i = 0; i < len; ++i)
						{
							if (i % 16 == 0)
							{
								printf("  ");
								if (i > 0) for (int x = 0; x < 16; x++) printf("%c", bin[i - 16 + x]);
								printf("\n");
								tabify(tabs + 1);
								printf("[0x%08zx] ", i);
							}

							printf("%02x ", (unsigned char)bin[i]);
						}
						hivex_free(bin);
					}
					printf("\n");
				}
				else
				{
					printf(" ...\n");
				}

			} break;
			default:
				printf(" **[unknown]**\n");
			}

		}
	}

	tabs--;
	hivex_free(values);
	values = NULL;
	++tabs;
	hive_node_h* children = hivex_node_children(hive, node);
	if (children != nullptr)
	{

		for (c = 0; children[c] != 0; ++c)
		{
			printnode(hive, children[c], hexDump);
		}
		hivex_free(children);
		children = nullptr;
	}
	--tabs;
}

#endif // __HIVEX_PRINTNODES_H__