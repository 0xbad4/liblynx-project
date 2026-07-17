#!/bin/python

import subprocess
import sys
import os
import pathlib

# make output directory
outdir = pathlib.Path("output")
outdir.mkdir(exist_ok=True)

# print usage
if len(sys.argv) < 2:
    print("python run.py <filename> <output/optional>")
    print("proceed with '%' to autocomplete protocol example filename.")
    exit(1)


# get filename
target = sys.argv[1]

if target.startswith("%"):
    target = target[1:]
    filename = "%s_craft.cpp" % target
else:
    filename = target


# check existence of input file
if (not os.path.exists(filename)):
    print("error: file not found")
    exit(1)


# get output filename
if len(sys.argv) > 2:
    output = sys.argv[2].replace(".cpp", "")
else:
    output = "%s.bin" % target.replace(".cpp", "")

output = outdir / output
cmd = ["g++", "-std=c++23", "-I../../include", filename, "-o", output]

# execute
print("cmd: ", cmd)
ec = subprocess.call(cmd)
print("exit code: ", ec)


if ec == 0 and os.path.exists(output):
    y = input("execute %s (Y/n) " %output) or "y"

    if y.lower() != "y":
        exit(0)
    else:
        subprocess.call([output])
