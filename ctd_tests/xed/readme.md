# Instructions for differential testing for CTD

## 1. Download and build our ground truth - xed

Visit [xed](https://github.com/intelxed/xed) to build. Specially, we need to build **examples**.

It's expected to have `$XED_DIR/obj/wkit/bin/xed` executable and export the path as `$XED_BIN`.

## 2. Build CTD

Run `./build_ctd.sh` at ctd folder

## 3. Set CTD env

Set `$CTD_BIN` to the folder containing `ctd_test` as executable 

## 4. Launch test & wait

Run `run_op1_test.sh` to test 1-byte opcode instructions and `run_op2_test.sh` to test 2-byte opcode instructions.

Get the result in the log file. In the log file, the output looks like

        f34f0f18bfdeadbeefdeadbeef 342620 344092 True
        [instruction-in-hex] [passed] [total] Does-CTD-output-no-memory-access?

It's expected to get no **False** across all the log files. The last line is [passed] and [total]. 