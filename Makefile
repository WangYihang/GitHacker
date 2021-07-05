test: build
	twine upload --skip-existing --repository-url https://test.pypi.org/legacy/ dist/*
release: build
	twine upload --skip-existing dist/*
build:
	python3 setup.py sdist bdist_wheel
	twine check dist/*
clean:
	rm -rf build dist *.egg-info