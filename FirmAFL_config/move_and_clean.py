import os
import string


dir_names = os.listdir(".")
image_dir_list = []
work_dir_list = []

image_dir_list = ["image_9050", "image_9054", "image_10566", 
"image_10853", "image_9925", "image_105600", "image_105609",
"image_129780", "image_129781", "image_161160", "image_161161"]

for dir_name in dir_names:
	'''
	if("image" in dir_name):
		image_dir_list.append(dir_name)
	'''
	if("work" in dir_name):
		work_dir_list.append(dir_name)


for image_dir in image_dir_list:
	cmdstr = "rm -r %s/outputs" %(image_dir)
	os.system(cmdstr)

for image_dir in image_dir_list:
	for work_dir in work_dir_list:
		cmdstr="cp -r %s %s/" %(image_dir, work_dir)
		print cmdstr
		os.system(cmdstr)

