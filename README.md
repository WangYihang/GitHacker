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
