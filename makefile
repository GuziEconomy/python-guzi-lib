init:
    pipenv install

test:
    pipenv run pytest

.PHONY: init test
