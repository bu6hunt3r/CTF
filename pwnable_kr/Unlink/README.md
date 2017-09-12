# pwnable.kr - unlink

- The goal of this challenge is to gain RCE via a variant of unlink macro used by libc.
- In simplified terms this program will release an node out of a double linked list that we fully control.

The routine that is responsible for unlinking a node out of double linked list gave me flashbacks on famous ```unlink()``` macro implemented in dlmalloc/ptmalloc, but with no security mitigations.

