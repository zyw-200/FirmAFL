import os
import string

image_list = ["image_9050", "image_9054", "image_10566", 
"image_10853", "image_9925", "image_105600", "image_105609",
"image_127980", "image_127981", "image_161160", "image_161161"]

dir_names = os.listdir("../")
print dir_names
image_dir_list = []
for dir_name in dir_names:
	if "image" in dir_name and dir_name in image_list:
		image_dir_list.append(dir_name)

for image_dir in image_dir_list:
	print image_dir
	os.chdir("../"+image_dir)
	os.system("cp ../FirmAFL_config/file_trans.sh .")
	str = image_dir.split("_")
	id = string.atoi(str[1])
	print id

	if id!=9050:
		cmd = "./file_trans.sh %d mips" %id
	else:
		cmd = "./file_trans.sh %d mipsel" %id
	os.system(cmd)


