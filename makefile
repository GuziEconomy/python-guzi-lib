.PHONY: init test

init:
	pipenv install

test:
	pipenv run pytest

format:
	pipenv run black guzilib tests
	pipenv run isort guzilib tests
	pipenv run flake8
