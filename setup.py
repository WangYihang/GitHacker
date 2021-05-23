import setuptools
import GitHacker

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="GitHacker",
    version=GitHacker.__version__,
    author="Wang Yihang",
    author_email="wangyihanger@gmail.com",
    description="This is a multiple threads tool to download the `.git` folder and rebuild git repository locally.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/WangYihang/Platypus-Python",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 5 - Production/Stable",
        "Topic :: Security",
        "Topic :: Software Development :: Version Control :: Git",
        "Topic :: Software Development :: Version Control",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
    ],
    python_requires=">=3.6",
    keywords="ctf, git, web, security",
    install_requires=["requests", "coloredlogs", "GitPython",
                      "beautifulsoup4", "semver", "termcolor"],
    entry_points={
        "console_scripts": [
            "githacker=GitHacker:main",
        ],
    },
)
