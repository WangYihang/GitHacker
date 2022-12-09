# GitHacker

[![PyPI version](https://badge.fury.io/py/GitHacker.svg)](https://badge.fury.io/py/GitHacker)
[![PyPI download](https://img.shields.io/pypi/dm/githacker.svg)](https://pypistats.org/packages/githacker)

## Desciption

This is a multiple threads tool to exploit the `.git` folder leakage vulnerability. It is able to download the target `.git` folder almost completely. This tool also works when the `DirectoryListings` feature is disabled by brute forcing common `.git` folder files.

With GitHacker's help, you can view the developer's commit history, branches, ..., stashes, which makes a better understanding of the target repo, even to find security vulnerabilities.

## PROCLAMATION (IMPORTANT)

> Several VULNERABILITIES have been reported recently, if you are using 
> GitHacker <= 1.1.0, please update your tool as soon as possible.

The remote `.git` folder maybe malicious, so to prevent you from being attacked.
It's highly recommended that you SHOULD run this tool under a disposable jailed environment 
(eg: Docker container).

## Requirments

* git >= 2.11.0
* Python 3

## Usage in Docker (Recommended)

```bash
# print help info
docker run wangyihang/githacker --help
# quick start
docker run -v $(pwd)/results:/tmp/githacker/results wangyihang/githacker --output-folder /tmp/githacker/results --url http://127.0.0.1/.git/
# brute for the name of branchs / tags
docker run -v $(pwd)/results:/tmp/githacker/results wangyihang/githacker --brute --output-folder /tmp/githacker/results --url http://127.0.0.1/.git/
# exploit multiple websites, one site per line
docker run -v $(pwd)/results:/tmp/githacker/results wangyihang/githacker --brute --output-folder /tmp/githacker/results --url-file websites.txt 
```

## Usage

```bash
# install
python3 -m pip install -i https://pypi.org/simple/ GitHacker
# print help info
githacker --help
# quick start
githacker --url http://127.0.0.1/.git/ --output-folder result
# brute for the name of branchs / tags
githacker --brute --url http://127.0.0.1/.git/ --output-folder result
# exploit multiple websites, one site per line
githacker --brute --url-file websites.txt --output-folder result
```

## Comparison of other tools

> 2021-05-25

|     Tools     |       Index        |    Source Code     |      Reflogs       |      Stashes       |      Commits       |      Branches      |      Remotes       |        Tags        |
| :-----------: | :----------------: | :----------------: | :----------------: | :----------------: | :----------------: | :----------------: | :----------------: | :----------------: |
|   GitTools    | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |        :x:         | :heavy_check_mark: |        :x:         | :heavy_check_mark: |        :x:         |
|  dvcs-ripper  | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |        :x:         | :heavy_check_mark: |        :x:         | :heavy_check_mark: |        :x:         |
|    GitHack    | :heavy_check_mark: | :heavy_check_mark: |        :x:         |        :x:         |        :x:         |        :x:         |        :x:         |        :x:         |
|  git-dumper   | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| **GitHacker** | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
|   GitTools    |        :x:         | :heavy_check_mark: | :heavy_check_mark: |        :x:         | :heavy_check_mark: |        :x:         | :heavy_check_mark: |        :x:         |
|  dvcs-ripper  |        :x:         |        :x:         |        :x:         |        :x:         |        :x:         |        :x:         |        :x:         |        :x:         |
|    GitHack    |        :x:         | :heavy_check_mark: |        :x:         |        :x:         |        :x:         |        :x:         |        :x:         |        :x:         |
|  git-dumper   |        :x:         | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |        :x:         | :heavy_check_mark: |        :x:         |
| **GitHacker** |        :x:         | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |      :muscle:      | :heavy_check_mark: |      :muscle:      |

## Example

![Demo](./figure/demo.gif)

## TODO

- [x] ~~Download packed files firstly~~ (Unsolvable via [StackOverflow](https://stackoverflow.com/questions/27789484/how-does-git-know-the-sha1-name-of-the-pack-files))
- [x] Fix infinit downloading 404 files, #25
- [x] Fix error when `master` branch not exists, #18
- [x] Extract branch names from `.git/logs/HEAD`, #18
- [x] Publish Docker image to hub.docker.com
- [x] Add Dockerfile
- [x] Fix stash files missing due to the fix of #21, #23, #24 (`git clone` can't download stash files)
- [x] Use python f'string in `test.py`
- [x] Download tags and branches when Index enabled
- [x] Try common tags and branches when Index disabled
- [x] [find packed refs](https://github.com/WangYihang/GitHacker/issues/1#issuecomment-487135667)

## Test

### Setup Development Environment

```
# Install docker and docker-compose
apt install docker-desktop
apt install docker-compose

# Download GitHacker
git clone https://github.com/WangYihang/GitHacker
cd GitHacker
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run tests

```
# Generate testing repo
python utils/gen.py

# Run testcases
sudo su
source venv/bin/activate
pip install -r requirements.txt
python utils/test.py
exit

# Diff results
python utils/diff.py
```

## Check report

See `test/report/YYYY-MM-DD/index.html`

## Videos
### asciinema

[![asciicast](https://asciinema.org/a/xgRmZ9dNvzhe3T2XRYDJe15Rj.png)](https://asciinema.org/a/xgRmZ9dNvzhe3T2XRYDJe15Rj)

### YouTube
* [【.git/ folder attack】Comparison of attack tools (Part I)](https://www.youtube.com/watch?v=Bs3QpVGf2uk)
* [【.git/ folder attack】Comparison of attack tools (Part II)](https://www.youtube.com/watch?v=Xzg4kQt4qEo)

## Security Issues

#### 2021-08-01 [Fixed](https://github.com/WangYihang/GitHacker/commit/e105b5c04329e9c4b8080029976bc73d12b1f23f): Malicious .git folder maybe harmful to the user of this tool (Reported by [Driver Tom](https://drivertom.blogspot.com))

* [别想偷我源码：通用的针对源码泄露利用程序的反制（常见工具集体沦陷）](https://drivertom.blogspot.com/2021/08/git.html)

#### 2022-03-01 [Fixed](https://github.com/WangYihang/GitHacker/commit/806095e807d20e06d5f192928f1f525510a34688): Arbitrary file write via recursive file downloader (Reported by [Justin Steven](https://twitter.com/justinsteven))

* To be released

#### 2022-03-01 [Fixed](https://github.com/WangYihang/GitHacker/commit/f97710c2cf0351308fc81666448e00004b7d14f9): Remote Code Execution via malicious `.git/config` and `.git/hooks/*` files (Reported by [Justin Steven](https://twitter.com/justinsteven))

* To be released

## References

* [Git Repository Layout](https://mirrors.edge.kernel.org/pub/software/scm/git/docs/gitrepository-layout.html)
* [Git Documents](https://git-scm.com/docs)
* [Git Pack filename](https://stackoverflow.com/questions/27789484/how-does-git-know-the-sha1-name-of-the-pack-files)

## Acknowledgement

- [@Justin Steven](https://twitter.com/justinsteven)
- [@Driver Tom](https://drivertom.blogspot.com)
- [@lesion1999](https://github.com/lesion1999)
- [@shashade250](https://github.com/shashade250)

## Licsence
```
THE DRINKWARE LICENSE

<wangyihanger@gmail.com> wrote this file. As long as 
you retain this :x:tice you can do whatever you want 
with this stuff. If we meet some day, and you think 
this stuff is worth it, you can buy me the following
drink(s) in return.

Red Bull
JDB
Coffee
Sprite
Cola
Harbin Beer
etc

Wang Yihang
```
