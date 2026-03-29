"""
Compare recovered git repository against the original, producing per-feature accuracy metrics.
Outputs structured JSON results.
"""

import hashlib
import json
import logging
import os

import coloredlogs

coloredlogs.install(fmt='%(asctime)s %(levelname)s %(message)s')


def md5(data):
    if isinstance(data, str):
        data = bytes(data, encoding='utf-8')
    return hashlib.md5(data).hexdigest()


def diff_files(origin_path, recovered_path, file_list):
    """
    Compare a list of files (relative paths) between origin and recovered repos.
    Returns (correct, total, different_files, absent_files).
    """
    correct = 0
    total = 0
    different = []
    absent = []

    for rel_path in file_list:
        origin_file = os.path.join(origin_path, rel_path)
        recovered_file = os.path.join(recovered_path, rel_path)

        if not os.path.isfile(origin_file):
            continue

        total += 1

        # Skip .git/index comparison (always differs)
        if os.path.join('.git', 'index') in rel_path:
            correct += 1
            continue

        if not os.path.exists(recovered_file):
            absent.append(rel_path)
            continue

        origin_md5 = md5(open(origin_file, 'rb').read())
        recovered_md5 = md5(open(recovered_file, 'rb').read())
        if origin_md5 == recovered_md5:
            correct += 1
        else:
            different.append(rel_path)

    return correct, total, different, absent


def diff_repo(origin_path, recovered_path, manifest):
    """
    Compare repos using manifest to produce per-feature results.
    Returns a dict with overall + per-feature metrics.
    """
    features = {}
    total_correct = 0
    total_files = 0

    for feature, file_list in manifest.items():
        correct, total, different, absent = diff_files(
            origin_path, recovered_path, file_list,
        )
        ratio = (correct / total * 100) if total > 0 else 0.0
        supported = ratio > 0  # feature is "supported" if any files recovered

        features[feature] = {
            'correct': correct,
            'total': total,
            'ratio': round(ratio, 2),
            'supported': supported,
            'different_files': different,
            'absent_files': absent,
        }

        total_correct += correct
        total_files += total

        ratio_str = f"{ratio:.2f}"
        log_msg = f"  {feature}: [{correct}/{total}] = {ratio_str}%"
        if ratio == 100.0:
            logging.info(log_msg)
        elif ratio > 0:
            logging.warning(log_msg)
        else:
            logging.error(log_msg)

    overall_ratio = (total_correct / total_files * 100) if total_files > 0 else 0.0

    return {
        'correct': total_correct,
        'total': total_files,
        'ratio': round(overall_ratio, 2),
        'different_files': [
            f for feat in features.values() for f in feat['different_files']
        ],
        'absent_files': [
            f for feat in features.values() for f in feat['absent_files']
        ],
        'features': {
            name: {
                'supported': feat['supported'],
                'correct': feat['correct'],
                'total': feat['total'],
                'ratio': feat['ratio'],
            }
            for name, feat in features.items()
        },
    }


def main():
    """Standalone diff for quick testing."""
    import glob as globmod

    origin_path = './test/repo'
    manifest_path = os.path.join(origin_path, 'manifest.json')

    if not os.path.exists(manifest_path):
        logging.error(f"Manifest not found: {manifest_path}. Run gen.py first.")
        return

    with open(manifest_path) as f:
        manifest = json.load(f)

    results = {}
    for folder in globmod.glob('./playground/*'):
        scenario = os.path.basename(folder)
        recovered_paths = globmod.glob(f"{folder}/*")
        if not recovered_paths:
            continue
        recovered_path = recovered_paths[0]

        logging.info(f"Comparing: {scenario}")
        results[scenario] = diff_repo(origin_path, recovered_path, manifest)

    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
