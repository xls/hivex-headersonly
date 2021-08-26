# hivex-headersonly

This a header-only version of the great hivex library by Richard W.M. Jones, for more information about the derived code see below.

Sample code enumerates all hive nodes and prints to console.
sample code also includes TinySha1 for calculating digest - by Saurav Mohapatra (https://github.com/mohaps/TinySHA1)
extra contains:




```c++

 void simple_example()
{
	hive_h* hive = hivex_open("test.bcd", 0);
	hive_node_h root = hivex_root(hive);

	hive_node_h *child_it, *pchildren = hivex_node_children(hive, root);
	child_it = pchildren;
	while (*child_it != 0)
	{
		hive_value_h* val_it, * pvalues;
		val_it = pvalues = hivex_node_values(hive, *child_it);
		while (*val_it != 0)
		{
			hive_value_h value = *val_it++;
			char* kname = hivex_value_key(hive, value);
			puts(kname);
		}

		hivex_free(pvalues);
		child_it++;
	}
	hivex_free(pchildren);
	hivex_close(hive);
}
```

TODO List:
- [ ] replace console ouput logging.
- [ ] create a c++ wrapper.



Original hivex code from https://github.com/libguestfs/hivex
----------------------------------------------------------------------

hivex - by Richard W.M. Jones, rjones@redhat.com
Copyright (C) 2009-2010 Red Hat Inc.

----------------------------------------------------------------------
This is a self-contained library for reading and writing Windows
Registry "hive" binary files.

Unlike many other tools in this area, it doesn't use the textual .REG
format for output, because parsing that is as much trouble as parsing
the original binary format.  Instead it makes the file available
through a C API, or there is a separate program to export the hive as
XML.

This library was derived from several sources:

 . NTREG registry reader/writer library by Petter Nordahl-Hagen
    (LGPL v2.1 licensed library and program)
 . http://pogostick.net/~pnh/ntpasswd/WinReg.txt
 . dumphive (a BSD-licensed Pascal program by Markus Stephany)
 . http://www.sentinelchicken.com/data/TheWindowsNTRegistryFileFormat.pdf
 . editreg program from Samba - this program was removed in later
   versions of Samba, so you have to go back in the source repository
   to find it (GPLv2+)
 . http://amnesia.gtisc.gatech.edu/~moyix/suzibandit.ltd.uk/MSc/
 . reverse engineering the format (see lib/tools/visualizer.ml)
