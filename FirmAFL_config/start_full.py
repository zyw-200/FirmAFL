import subprocess
import time
import os
import shutil
import sys

id=sys.argv[1]

cmdstr ="python sleep_and_test.py %s" %id
subprocess.Popen(cmdstr,stdin=subprocess.PIPE,shell=True)
cmdstr ="./run_full.sh"
os.system(cmdstr)

