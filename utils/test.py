import subprocess
import os


def start_docker(docker_compose_yml_folder):
    cwd = os.getcwd()
    os.chdir(docker_compose_yml_folder)
    os.system("docker-compose up -d")
    os.chdir(cwd)


def stop_docker(docker_compose_yml_folder):
    cwd = os.getcwd()
    os.chdir(docker_compose_yml_folder)
    os.system("docker-compose down")
    os.chdir(cwd)


def test_githacker(folder, url):
    start_docker(folder)
    subprocess.check_output([
        "python3",
        "GitHacker/__init__.py",
        "--brute",
        "--url",
        url,
        "--output-folder",
        f"playground/{os.path.basename(folder)}",
    ])
    stop_docker(folder)


def test_apache_index_enabled():
    test_githacker(
        folder="./test/docker/apache-index-enabled",
        url="http://127.0.0.1/",
    )


def test_apache_index_disabled():
    test_githacker(
        folder="./test/docker/apache-index-disabled",
        url="http://127.0.0.1/",
    )


def test_nginx_index_enabled():
    test_githacker(
        folder="./test/docker/nginx-index-enabled",
        url="http://127.0.0.1/",
    )


def test_nginx_index_disabled():
    test_githacker(
        folder="./test/docker/nginx-index-disabled",
        url="http://127.0.0.1/",
    )


def test_php_lfi():
    test_githacker(
        folder="./test/docker/php-lfi",
        url="http://127.0.0.1/lfi.php?file=./",
    )


def main():
    test_apache_index_enabled()
    test_apache_index_disabled()
    test_nginx_index_enabled()
    test_nginx_index_disabled()
    test_php_lfi()


if __name__ == "__main__":
    main()
