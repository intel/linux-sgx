To build and run:
```
$ make clean
$ make
$ ./app
```

If the test succeeds, it will print out the register contents before and after the most recent interrupt.

The test fails if an assertion fails.

The test triggers a #UD exception. When control is retured to the enclave, a
ud_handler moves RIP to point to the next instruction, a MOV to memory. The
CTD will decode this instruction and determine the memory address. The test
performs two checks:
1. That the memory address determined by the CTD is correct
2. That the CPU context (i.e., registers) remain unchanged by the mitigation
