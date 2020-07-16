import sys
import os

firm_id = sys.argv[1]
firm_arch = sys.argv[2]
firm_dir = "image"+firm_id

sys_run_src = "firmadyne/scratch/%s/run.sh" %firm_id
#sys_run_src = "FirmAFL_config/%s/run.sh" %(firm_id)
user_run_src = "FirmAFL_config/user.sh"
if "mips" in firm_arch:
	sys_src = "qemu_mode/DECAF_qemu_2.10/%s-softmmu/qemu-system-%s" %(firm_arch, firm_arch)
	user_src = "user_mode/%s-linux-user/qemu-%s" %(firm_arch, firm_arch)
else:
	sys_src = "qemu_mode/DECAF_qemu_2.10/arm-softmmu/qemu-system-arm"
	user_src = "user_mode/arm-linux-user/qemu-arm" 
config_src = "FirmAFL_config/%s/FirmAFL_config" %(firm_id)
test_src = "FirmAFL_config/%s/test.py" %(firm_id)
keywords_src = "FirmAFL_config/%s/keywords" %(firm_id)
afl_src= "FirmAFL_config/afl-fuzz"
firmadyne_src = "firmadyne/firmadyne.config"
image_src = "firmadyne/scratch/%s/image.raw" %firm_id
if "mips" in firm_arch:
	kernel_src ="firmadyne_modify/vmlinux.%s_3.2.1" %firm_arch
else:
	kernel_src ="firmadyne_modify/zImage.armel"
procinfo_src =  "FirmAFL_config/procinfo.ini"
other_file1 =  "FirmAFL_config/efi-pcnet.rom"
other_file2 =  "FirmAFL_config/vgabios-cirrus.bin"
cmd_input = "mkdir image_%s/inputs" %firm_id
seed_src = "FirmAFL_config/%s/seed" %(firm_id)
start_src = "FirmAFL_config/start.py"

dst = "image_%s/" %firm_id
dst_input = "image_%s/inputs/" %firm_id

cmd = []
cmd.append("cp %s %s" %(sys_run_src, dst)) 
cmd.append("cp %s %s" %(user_run_src, dst)) 
cmd.append("cp %s %s" %(sys_src, dst)) 
cmd.append("cp %s %safl-qemu-trace" %(user_src, dst)) 
cmd.append("cp %s %s" %(config_src, dst)) 
cmd.append("cp %s %s" %(test_src, dst)) 
cmd.append("cp %s %s" %(keywords_src, dst)) 
cmd.append("cp %s %s" %(afl_src, dst)) 
cmd.append("cp %s %s" %(firmadyne_src, dst)) 
cmd.append("cp %s %s" %(image_src, dst)) 
cmd.append("cp %s %s" %(kernel_src, dst))
cmd.append("cp %s %s" %(procinfo_src, dst)) 
cmd.append("cp %s %s" %(other_file1, dst)) 
cmd.append("cp %s %s" %(other_file2, dst)) 
cmd.append(cmd_input)
cmd.append("cp %s %s" %(seed_src, dst_input)) 
cmd.append("cp %s %s" %(start_src, dst)) 

for i in range(0, len(cmd)):
	os.system(cmd[i])
