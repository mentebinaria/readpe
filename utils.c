/*
	libpe - the PE library

	Copyright (C) 2010 - 2014 libpe authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int loadconfig(const char *path, callback_t cb)
{
	FILE *fp = fopen(path, "r");
	puts(path);

   if (fp == NULL)
      return -1;

   char line[1024];
   while (fgets(line, sizeof(line), fp))
   {
      // comments
      if (*line == '#')
         continue;

      // remove newline
      for (int i=0; i < sizeof(line); i++)
      {
         if (line[i] == '\n' || i == sizeof(line)-1)
         {
            line[i] = '\0';
            break;
         }
      }
      const char *param = strtok(line, "=");
      const char *value = strtok(NULL, "=");

		cb(param, value);
   }
	fclose(fp);
	return 0;
}
