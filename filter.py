import os

def file_path(path):
	for (root, dirs, files) in os.walk(path):
		for file in files:
			del_small_file(root + '/' + file)

def del_small_file(file_name):
	size = os.path.getsize(file_name)
	file_size = 2 * 1024
	if size < file_size:
		os.remove(file_name)

if __name__ == '__main__':
	path = r'./CNVD'
	file_path(path)