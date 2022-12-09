import glob
import os
import logging
import coloredlogs
import verboselogs
import datetime
from jinja2 import Environment, FileSystemLoader

verboselogs.install()
logger = logging.getLogger(__name__)
coloredlogs.install(logger=logger)

env = Environment(loader=FileSystemLoader("templates/"))


def md5(data):
    if type(data) is str:
        data = bytes(data, encoding="utf-8")
    return __import__("hashlib").md5(data).hexdigest()


def diff(left, right):
    visible_files = glob.glob(f"{left}/**/*", recursive=True)
    invisiable_files = glob.glob(f"{left}/**/.*", recursive=True)
    git_files = glob.glob(f"{left}/.git/**/*", recursive=True)
    files = visible_files + invisiable_files + git_files
    total = 0
    correct = 0
    difference = []
    absence = []
    for filename in files:
        if os.path.isfile(filename):
            total += 1
            current_filename = filename.replace(left, right)
            if not os.path.exists(current_filename):
                absence.append(current_filename)
                continue

            # There is no need to compare the `.git/index` file, leave it as correct
            if os.path.join(".git", "index") in filename:
                correct += 1
                continue

            origin_md5 = md5(open(filename, "rb").read())
            current_md5 = md5(open(current_filename, "rb").read())
            if origin_md5 == current_md5:
                correct += 1
            else:
                difference.append(filename)

    return (correct, total, difference, absence)


def diffall(display_difference=False, display_abscences=False):
    results = {}
    for folder in glob.glob("./test/docker/*"):
        basename = os.path.basename(folder)
        origin_path = os.path.join("test", "repo")
        current_paths = glob.glob(f"{os.path.join('playground', basename)}/*")
        if len(current_paths) == 0:
            continue
        current_path = current_paths[0]

        # Calculate differences
        correct, total, difference, abscence = diff(origin_path, current_path)
        # Display correct ratio
        ratio = (correct / total) * 100

        results[basename] = {
            "correct": correct,
            "total": total,
            "difference": difference,
            "abscence": abscence,
            "ratio": ratio,
        }

        ratio_log = f"[{correct} / {total}] = {ratio:.2f}%, {origin_path}, {current_path}"
        if ratio == 100.0:
            logger.info(ratio_log)
        else:
            logger.warning(ratio_log)

        # Display different files
        if len(difference) > 0 and display_difference:
            logger.info("  Different files:")
            for filename in difference:
                logger.error(f"    {filename}")

        # Display absent files
        if len(abscence) > 0 and display_abscences:
            logger.info("  Files absent:")
            for filename in abscence:
                logger.error(f"    {filename}")

        # Render report
        template = env.get_template("result.html")
        html = template.render(
            {
                "tool": "GitHacker",
                "time": datetime.datetime.now(),
                "correct": correct,
                "total": total,
                "ratio": ratio,
                "difference": difference,
                "abscence": abscence,
            }
        )
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        report_filepath = f"test/report/{today}/{basename}.html"
        try:
            os.makedirs(os.path.dirname(report_filepath))
        except Exception as e:
            logger.error(repr(e))
        with open(report_filepath, "w") as f:
            f.write(html)

    template = env.get_template("index.html")
    html = template.render({"results": results})
    report_filepath = f"test/report/{today}/index.html"
    try:
        os.makedirs(os.path.dirname(report_filepath))
    except Exception as e:
        logger.error(repr(e))
    with open(report_filepath, "w") as f:
        f.write(html)


def main():
    diffall(
        display_difference=True,
        display_abscences=True,
    )


if __name__ == "__main__":
    main()
