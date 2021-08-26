// hivex.cpp : Defines the entry point for the console application.
//

#include "hivex/hivex.h"
#include "extras/hashnodes.h"
#include "extras/printnode.h"
#include "extras/findnode.h"
#include "extras/sha1.h"
#include <string>



int total_len = 0;



void hasher(void *ctx, const unsigned char *in, unsigned long inlen)
{
	sha1::SHA1* sha1 = (sha1::SHA1*)ctx;
	sha1->processBytes(in, inlen);
	total_len += inlen;

}

 /* 
 Example of how to get a sample BCD hive exported:
 
 # on Windows run: 
 > bcdedit /export "test.bcd"
 
 # copy test.bcd to program folder and run:
 > hivex test.bcd

  */

int main(int argc, const char** argv)
{
	printf("argc: %d\n", argc);
	
	char filename[1024];
	strcpy(filename, "user"); // default

	if (argc > 1)
		strcpy(filename, argv[1]);

	// lets get a digest for all entities in the hive (testing cross-platform/ cross)
	sha1::SHA1 sha1;
	hive_h* hive = hivex_open(filename, 0);
	
	if (hive != nullptr)
	{
		hive_node_h root = hivex_root(hive);

		printf("find key\n");
		
		// find a node and print it
		auto node = findkey(hive, root, "NewStoreRoot\\Objects\\{4662f11f-cbc8-11ea-b16f-b995a37ba28c}");
		if (node)
		{
			printf("print key\n");
			printnode(hive, node);
		}
		

		
		// print root node and its children
		printnode(hive, root,true);


		// hash all nodes -> hash(size+key+value);
		hashenumerate(hasher, &sha1, hive, root);
		
		hivex_close(hive);

		sha1::SHA1::digest8_t digest;
		sha1.getDigestBytes(digest);

		printf("\n------------------------------------------------\n");
		printf("hash: ");
		for (int i = 0; i < 20; ++i)
		{
			printf("%02x", digest[i]);
		}

		printf("\n");
		printf("totalLen: %d\n", total_len);
		printf("\n");
		
	}
	else
	{
		printf("usage:\n %s <path>\n", argv[0]);
		return 0;
	}
	
    return 0;
}

