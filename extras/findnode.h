#ifndef __HIVEX_FINDNODE_H__
#define __HIVEX_FINDNODE_H__

#ifndef HIVEX_H_
#include "hivex.h" /* or else make sure hivex.h is included before this tools */
#endif

/* 
example:
	auto node = findkey(hive, root, "NewStoreRoot\\Objects\\{4662f11f-cbc8-11ea-b16f-b995a37ba28c}");
	printnode(hive, node,true);
*/
hive_node_h findkey(hive_h* hive, hive_node_h node, const char* str)
{

	const char* p_ssearch = str;
	char* name = hivex_node_name(hive, node);
	size_t nlen = strlen(name);
	if (strncmp(str, name, nlen) == 0)
	{
		const char* p_stail = p_ssearch + nlen;
		if (*p_stail == '\\')
		{
			p_ssearch += nlen + 1;
			hive_node_h* p_children = hivex_node_children(hive, node);
			hive_node_h* p_iterator = p_children;
			while (*p_iterator != 0)
			{
				auto ret = findkey(hive, *p_iterator, p_ssearch);
				if (ret != 0)
					return ret;
				p_iterator++;
			}
			hivex_free(p_children);
		}
		else if (*p_stail == 0)
		{
			return node;
		}
	}

	return 0;
}

#endif // __HIVEX_FINDNODE_H__
