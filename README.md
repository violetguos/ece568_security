# security

# N.B.
if you are currently enrolled in ECE568 at University of Toronto and poking around Github, close this tab right now.
good luck and DO NOT COPY!

## introduction
This is a small example from my past school project on memory exploit computer programs in C.

## Explanation
(quoted from ECE568 course materials)
Finding Buffer Overflows
                              ~~~~~~~~~~~~~~~~~~~~~~~~

   As stated earlier, buffer overflows are the result of stuffing more
information into a buffer than it is meant to hold.  Since C does not have any
built-in bounds checking, overflows often manifest themselves as writing past
the end of a character array.  The standard C library provides a number of
functions for copying or appending strings, that perform no boundary checking.
They include: strcat(), strcpy(), sprintf(), and vsprintf(). These functions 
operate on null-terminated strings, and do not check for overflow of the 
receiving string.  gets() is a function that reads a line from stdin into 
a buffer until either a terminating newline or EOF.  It performs no checks for
buffer overflows.  The scanf() family of functions can also be a problem if 
you are matching a sequence of non-white-space characters (%s), or matching a 
non-empty sequence of characters from a specified set (%[]), and the array 
pointed to by the char pointer, is not large enough to accept the whole 
sequence of characters, and you have not defined the optional maximum field 
width.  If the target of any of these functions is a buffer of static size, 
and its other argument was somehow derived from user input there is a good
posibility that you might be able to exploit a buffer overflow.
