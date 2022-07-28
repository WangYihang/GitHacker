import glob
import os
import logging
import coloredlogs

coloredlogs.install(fmt='%(asctime)s %(levelname)s %(message)s')


def md5(data):
    if type(data) is str:
        data = bytes(data, encoding='utf-8')
    return __import__('hashlib').md5(data).hexdigest()


def diff(left, right):
    visible_files = glob.glob(f"{left}/**/*", recursive=True)
    invisiable_files = glob.glob(f"{left}/**/.*", recursive=True)
    git_files = glob.glob(f"{left}/.git/**/*", recursive=True)
    files = visible_files + invisiable_files + git_files
    total = 0
    same = 0
    difference = []
    right_absence = []
    for filename in files:
        if os.path.isfile(filename):
            total += 1
            current_filename = filename.replace(left, right)
            if not os.path.exists(current_filename):
                right_absence.append(current_filename)
                continue

            # There is no need to compare the `.git/index` file, leave it as same
            if os.path.join(".git", "index") in filename:
                same += 1
                continue

            origin_md5 = md5(open(filename, "rb").read())
            current_md5 = md5(open(current_filename, "rb").read())
            if origin_md5 == current_md5:
                same += 1
            else:
                difference.append(filename)

    return (same, total, difference, right_absence)


def diffall(display_difference=False, display_abscences=False):
    for folder in glob.glob("./test/docker/*"):
        basename = os.path.basename(folder)
        origin_path = os.path.join('test', "docker", basename, "www")
        current_paths = glob.glob(f"{os.path.join('playground', basename)}/*")
        if len(current_paths) == 0:
            continue
        current_path = current_paths[0]
        same, total, difference, right_absence = diff(
            origin_path, current_path)
        ratio = (same / total) * 100
        if ratio == 100.0:
            logging.info(
                f"[{same} / {total}] = {ratio:.2f}%, {origin_path}, {current_path}")
        else:
            logging.warning(
                f"[{same} / {total}] = {ratio:.2f}%, {origin_path}, {current_path}")
        if len(difference) > 0 and display_difference:
            logging.info("  Different files:")
            for filename in difference:
                logging.error(f"    {filename}")
        if len(right_absence) > 0 and display_abscences:
            logging.info("  Files absent:")
            for filename in right_absence:
                logging.error(f"    {filename}")


def main():
    diffall(
        display_difference=True,
        display_abscences=True,
    )


if __name__ == "__main__":
    main()
