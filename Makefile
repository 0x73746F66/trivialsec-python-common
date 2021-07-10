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
	pip install --no-cache-dir --find-links=build/wheel --no-index dist/trivialsec_common-*-py2.py3-none-any.whl

install: ## Install trivialsec modules
	python3 setup.py check
	pip --no-cache-dir wheel --wheel-dir=build/wheel -r requirements.txt
	python3 setup.py bdist_wheel --universal
	pip install -q -U --no-cache-dir --find-links=build/wheel --no-index --isolated --no-warn-script-location dist/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl

install-deps: prep ## setup for development of this project
	pip install -q -U pip setuptools wheel semgrep pylint
	pip install -q -U --no-cache-dir --isolated -r requirements.txt

lint: ## checks code quality
	pylint --jobs=0 --persistent=y --errors-only trivialsec/**/*.py

sast: ## semgrep ci
	semgrep -q --strict --timeout=0 --config=p/ci --lang=py trivialsec/**/*.py

xss: ## checks for flask xss
	semgrep -q --strict --config p/minusworld.flask-xss --lang=py trivialsec/**/*.py

test-all: lint sast xss ## Run all CI tests

test-local: ## Prettier test outputs
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 trivialsec/**/*.py
	semgrep -q --strict --timeout=0 --config=p/ci --lang=py trivialsec/**/*.py
	semgrep -q --strict --config p/minusworld.flask-xss --lang=py trivialsec/**/*.py

archive: wheel ## packages as a tgz for distribution
	tar -ckzf $(APP_NAME).tgz build/wheel
	ls -l --block-size=M $(APP_NAME).tgz
