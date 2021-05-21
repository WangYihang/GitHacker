# GitHacker

## Desciption

This is a multiple threads tool to detect whether a site has the `.git` folder 
leakage vulnerability. It is able to download the target `.git` folder almost 
completely. This tool also works when the `DirectoryListings` feature is 
disabled. It is worth mentioning that this tool will download almost all files 
of the target git repository and then rebuild them locally, which makes this 
tool State of the art in this area. For example, tools like [githack] just 
simply restore the latest version. With GitHacker's help, you can view the 
developer's commit history, which makes a better understanding of the character 
and psychology of developers, so as to lay the foundation for further code 
audition.

## Comparison of other tools

![image.png](https://upload-images.jianshu.io/upload_images/2355077-64bde1bcf617e0cf.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)



## Requirments

* git >= 2.11.0
* Python 3

## Installation

```
pip3 install GitHacker # -i pypi mirror repo url
```

## Usage

```bash
githacker --url http://127.0.0.1/.git/ --folder result
```

## Example

![Demo](./figure/demo.gif)

## TODO

- [ ] Download tags and branches when Index enabled
- [x] Try common tags and branches when Index disabled
- [x] [find packed refs](https://github.com/WangYihang/GitHacker/issues/1#issuecomment-487135667)


## Videos
### asciinema

[![asciicast](https://asciinema.org/a/xgRmZ9dNvzhe3T2XRYDJe15Rj.png)](https://asciinema.org/a/xgRmZ9dNvzhe3T2XRYDJe15Rj)

### YouTube
* [【.git/ folder attack】Comparison of attack tools (Part ONE)](https://www.youtube.com/watch?v=Bs3QpVGf2uk)
* [【.git/ folder attack】Comparison of attack tools (Part TWO)](https://www.youtube.com/watch?v=Xzg4kQt4qEo)


## Acknowledgement
- [lesion1999](https://github.com/lesion1999)

## Licsence
```
THE DRINKWARE LICENSE

<wangyihanger@gmail.com> wrote this file. As long as 
you retain this notice you can do whatever you want 
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
