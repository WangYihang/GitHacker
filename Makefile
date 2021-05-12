test: build
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*
release: build
	twine upload dist/* --skip-existing
build:
	python setup.py sdist bdist_wheel
	twine check dist/*