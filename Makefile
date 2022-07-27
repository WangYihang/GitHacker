publish_test: build
	twine upload --skip-existing --repository-url https://test.pypi.org/legacy/ dist/*
publish_release: build
	twine upload --skip-existing dist/*
publish_docker: build
	docker build -t wangyihang/githacker:latest .
	docker push wangyihang/githacker:latest
build:
	python3 setup.py sdist bdist_wheel
	twine check dist/*
clean:
	rm -rf build dist *.egg-info