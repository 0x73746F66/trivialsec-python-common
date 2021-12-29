SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
APP_NAME = trivialsec

.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

prep: ## cleans python for wheel
	@find . -type f -name '*.pyc' -delete 2>/dev/null
	@find . -type d -name '__pycache__' -delete 2>/dev/null
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null
	@rm -rf build dist trivialsec_common.egg-info
	@rm -f **/*.zip **/*.tgz **/*.gz

wheel: prep ## builds python wheel files
	pip uninstall -y trivialsec-common || true
	python3 setup.py check && pip --no-cache-dir wheel --wheel-dir=build/wheel -r requirements.txt && \
		python3 setup.py bdist_wheel --universal
	pip install --no-cache-dir --find-links=build/wheel --no-index dist/trivialsec_common-$(TRIVIALSEC_PY_LIB_VER)-py2.py3-none-any.whl

setup: prep ## setup for development of this project
	pip install -q -U pip setuptools wheel semgrep pylint
	pip install -q -U -r requirements.txt

install: ## Install trivialsec modules
	python3 setup.py check
	python3 setup.py sdist bdist_wheel
	pip install -q -U --no-cache-dir --force-reinstall dist/trivialsec_common-$(TRIVIALSEC_PY_LIB_VER)-py2.py3-none-any.whl

archive: wheel ## packages as a tar.gz for distribution
	tar -ckzf $(APP_NAME).tar.gz build/wheel
	ls -l --block-size=M $(APP_NAME).tar.gz

test-local: ## Prettier test outputs
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py
	semgrep -q --strict --config p/minusworld.flask-xss --lang=py src/**/*.py

pylint-ci: ## run pylint for CI
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

semgrep-xss-ci: ## run Flask XSS semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-flask-xss.json --json --config p/minusworld.flask-xss --lang=py src/**/*.py

test-all: semgrep-xss-ci semgrep-sast-ci pylint-ci ## Run all CI tests

publish: ## force tag and push version
	git tag -f ${TRIVIALSEC_PY_LIB_VER}
	git push -f origin ${TRIVIALSEC_PY_LIB_VER}
