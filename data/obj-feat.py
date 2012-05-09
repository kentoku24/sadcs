import os
import sys
import fileinput
from Tkinter import *
import tkFileDialog

master = Tk()
master.withdraw()
master_path = tkFileDialog.askdirectory()
#print "Parsing: ", path

html_start = False
html_end = False
KB_val = 0.0009765625
obj_vector = []
html_file = 0
me = sys.argv[0].split("\\")[-1]

vector_hash = {}

for dir in os.listdir(master_path):
    print dir
    for filename in os.listdir(master_path+"/"+dir):
        path = master_path+"/"+dir
#        print filename
        if filename == me:
            continue
        filename = path+"/"+filename
        if not html_start and not html_end:
            try:
                f = open(filename, "r")
                for line in f:
                    if line.rfind("<html") != -1:
                        html_start =  True
                    elif line.rfind("</html>") != -1:
                        html_end = True
            except:
#                print ''
                pass

        if html_start and html_end:
#           print "-----"
#           print "HTML=", filename
#           print "-----"
            html_file = int(os.path.getsize(filename))
            html_start =  False
            html_end = False
        else:
            obj_vector.append(int(os.path.getsize(filename)))

    obj_vector.sort()
    if html_file > 0:
        if str(obj_vector) in vector_hash:
            vector_hash[str(obj_vector)] += 1
        else:
            vector_hash[str(obj_vector)] = 1
        obj_vector = [html_file] + obj_vector


    print "\n",obj_vector
    size = sum(obj_vector)
    print "\nTotal size: ", size , "Bytes", "-->", KB_val*size, "KB"
    print "--------------------------------------------------------"
    obj_vector = []
    html_file = 0

print "TOTALS:"
for key in vector_hash.keys():
    print key, "=", vector_hash[key]
    
master.quit()
