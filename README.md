# GitHacker

#### Desciption: 
```
This is a multiple threads tool to detect whether a site has git source leaks,   
and has the ability to download the site source to the local  
This tool can even be in. Git directory is prohibited when access to the use of loopholes
It is worth mentioning that this tool will be, 
git directory completely simulated to the local rather than tools 
such as [githack] just simply restore to the latest version  
so that you can view the developer's submission history as well as submit the annotation 
you can be better To grasp the character and psychology of developers, 
so as to lay the foundation for further code audit
```

#### Why you need this tool not other tools
![image.png](https://upload-images.jianshu.io/upload_images/2355077-64bde1bcf617e0cf.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
* [【.git/ folder attack】Comparison of attack tools (Part ONE)](https://www.youtube.com/watch?v=Bs3QpVGf2uk)
* [【.git/ folder attack】Comparison of attack tools (Part TWO)](https://www.youtube.com/watch?v=Xzg4kQt4qEo)


#### Requirments:
```
git >= 2.11.0
python-requests
Linux envrionment
```

#### Installation: 
```
# Install requests
pip install requests
# Download source
# Notice: NO NOT DOWNLOAD ZIP FROM GITHUB
git clone https://github.com/wangyihang/GitHacker.git
```

#### Usage :
```
Usage :
        python GitHacker.py [Website]
Example :
        python Githack.py http://127.0.0.1/.git/
Author :
        wangyihang <wangyihanger@gmail.com>
```

#### Example: 
```
python GitHacker.py http://127.0.0.1/.git/
```

#### TODO:
- [ ] Download tags and branches when Index enabled
- [ ] Try common tags and branches when Index disabled
- [ ] [find packed refs](https://github.com/WangYihang/GitHacker/issues/1#issuecomment-487135667)
#### Video: 
[![asciicast](https://asciinema.org/a/xgRmZ9dNvzhe3T2XRYDJe15Rj.png)](https://asciinema.org/a/xgRmZ9dNvzhe3T2XRYDJe15Rj)

#### Licsence
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
