import os
import string
import sys

exp_times = sys.argv[1]

dir_names = os.listdir("../")
print dir_names
image_dir_list = []
for dir_name in dir_names:
	if("image" in dir_name):
		image_dir_list.append(dir_name)

for image_dir in image_dir_list:
	print image_dir
	image_str = image_dir.split("_")
	image_id = image_str[1]
	os.chdir("../"+image_dir)
	if os.path.exists("outputs") == 0:
		print("%s do not generate output" %image_id)
		continue
	
	os.chdir("../FirmAFL_results/")
	if os.path.exists(image_id) == 0:
		os.mkdir(image_id)
		print("mkdir dir %s" %image_id)

	os.chdir(image_id)
	output_dir = "outputs_%s" %exp_times
	if os.path.exists(output_dir) == 0:
		os.mkdir(output_dir)
	cmdstr = "cp -r ../../image_%s/outputs/* %s" %(image_id, output_dir)
	os.system(cmdstr)
	os.chdir("../../FirmAFL_config")

	