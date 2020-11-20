SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)

.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

CMD_AWS := aws
ifdef AWS_PROFILE
CMD_AWS += --profile $(AWS_PROFILE)
endif
ifdef AWS_REGION
CMD_AWS += --region $(AWS_REGION)
endif

prep: ## cleans python for wheel
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	find . -type d -name '__pycache__' -delete 2>/dev/null || true
	find . -type f -name '*.DS_Store' -delete 2>/dev/null || true

wheel: prep ## builds python wheel files
	rm -rf build dist trivialsec_common.egg-info
	pip uninstall -y trivialsec-common || true
	python3.8 setup.py check && pip --no-cache-dir wheel --wheel-dir=build/wheel -r requirements.txt && \
		python3.8 setup.py bdist_wheel --universal
	pip --use-feature=2020-resolver install --no-cache-dir --find-links=build/wheel --no-index dist/trivialsec_common-*-py2.py3-none-any.whl

install-dev: ## setup for development of this project
	pip install --use-feature=2020-resolver -q -U pip setuptools pylint wheel awscli
	pip install --use-feature=2020-resolver -q -U --no-cache-dir --isolated -r requirements.txt

lint: ## checks code quality
	pylint --jobs=0 --persistent=y --errors-only trivialsec/**/*.py

package: wheel
	rm -f **/*.zip
	zip -9rq build.zip build/wheel

package-upload: package
	$(CMD_AWS) s3 cp --only-show-errors dist/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl s3://cloudformation-trivialsec/deploy-packages/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl
	$(CMD_AWS) s3 cp --only-show-errors build.zip s3://cloudformation-trivialsec/deploy-packages/build-$(COMMON_VERSION).zip
