/*
	pev - the PE file analyzer toolkit

	cpload.c - CPL file loader

	Copyright (C) 2013 - 2014 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.
*/

#include <stdio.h>
#include <Windows.h>
#include <Cpl.h>

typedef int (*cplapplet) (void*,int,void*,void*);

int main(int argc, char* argv[])
{
	cplapplet _cplapplet;
	HINSTANCE dll;
	char* filename;
	CPLINFO cplinfo;
	NEWCPLINFO newcplinfo;
	char *msg;
	char* msgs[] = { "null",
		"init",
		"getcount",
		"inquire",
		"select",
		"dblclk",
		"stop",
		"exit",
		"newinquire",
		"null",
		"startwparms",
		"setup" };

	if (argc == 2)
		filename = argv[1]; // cpload file.cpl
	else if (argc == 4)
		filename = argv[3]; // cpload -m MESSAGE file.cpl
	else
	{
		printf(
			"\nUsage:\n\tcpload [-m MESSAGE] <file.cpl>\n\n"
			"If -m is present, MESSAGE should be:\n\n"
			"\tOption\t\tMessage\n"
			"\t------------------------------\n"
			"\tinit\t\tCPL_INIT\n"
			"\tgetcount\tCPL_GETCOUNT\n"
			"\tinquire\t\tCPL_INQUIRE\n"
			"\tselect\t\tCPL_SELECT\n"
			"\tdblclk\t\tCPL_DBLCLK\n"
			"\tstop\t\tCPL_STOP\n"
			"\texit\t\tCPL_EXIT\n"
			"\tnewinquire\tCPL_NEWINQUIRE\n"
			"\tstartwparms\tCPL_STARTWPARMS\n"
			"\tsetup\t\tCPL_SETUP\n"
			"\nOtherwise, cpload will send all messages to CPlApplet()\n"
			);
		return 1;
	}

	printf("loading library...\n");
	
	if (IsDebuggerPresent())
		__asm__("int $3");

	if (NULL == (dll = LoadLibrary(filename)))
	{
		fprintf(stderr, "file not found or not a valid CPL\n");
		return 1;
	}

	printf("looking for CPlApplet()...\n");
	_cplapplet = (cplapplet) GetProcAddress(dll, "CPlApplet");
	
	if (!_cplapplet)
	{
		fprintf(stderr, "CPlApplet function not found. Aborting...\n");
		return 1;
	}

	if (argc == 4)
	{
		msg = argv[2];

		for (int i=1; i<=11; i++)
		{
			if (i==9)
				continue;

			if (!strncmp(msg, msgs[i], strlen(msgs[i])))
			{
				if (IsDebuggerPresent())
					__asm__("int $3");

				printf("sending %s message...\n", msgs[i]);
				if (i == CPL_INQUIRE)
					_cplapplet(NULL, CPL_INQUIRE, 0, &cplinfo); // lParam1 is applet # - lParam2 is ptr to CPLINFO struct
				else if (i == CPL_NEWINQUIRE)
					_cplapplet(NULL, CPL_NEWINQUIRE, 0, &newcplinfo);
				else
					_cplapplet(NULL, i, NULL, NULL);
				
				break;
			}
			
		}
	}
	else // send all messages
	{
		if (IsDebuggerPresent())
			__asm__("int $3");

		_cplapplet(NULL, CPL_INIT, NULL, NULL);
		_cplapplet(NULL, CPL_GETCOUNT, NULL, NULL);
		_cplapplet(NULL, CPL_INQUIRE, 0, &cplinfo); // lParam1 is applet # - lParam2 is ptr to CPLINFO struct
		_cplapplet(NULL, CPL_SELECT, NULL, NULL);
		_cplapplet(NULL, CPL_DBLCLK, NULL, NULL);
		_cplapplet(NULL, CPL_STOP, NULL, NULL);
		_cplapplet(NULL, CPL_EXIT, NULL, NULL);
		_cplapplet(NULL, CPL_NEWINQUIRE, 0, &newcplinfo);
		_cplapplet(NULL, CPL_STARTWPARMS, NULL, NULL);
		_cplapplet(NULL, CPL_SETUP, NULL, NULL);
	}
	
	FreeLibrary(dll);
	return 0;
}
