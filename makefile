.PHONY: init test

init:
	pipenv install

test:
	pipenv run pytest

