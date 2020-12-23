.PHONY: init test

init:
	pipenv install

test:
	pipenv run pytest

format:
	pipenv run black guzilib test
	pipenv run isort guzilib test
	pipenv run flake8
