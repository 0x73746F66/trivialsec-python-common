SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
LOCAL_CACHE = /tmp/trivialsec

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
	rm -rf build dist trivialsec_common.egg-info
	rm -f **/*.zip **/*.gz

wheel: prep ## builds python wheel files
	pip uninstall -y trivialsec-common || true
	python3.8 setup.py check && pip --no-cache-dir wheel --wheel-dir=build/wheel -r requirements.txt && \
		python3.8 setup.py bdist_wheel --universal
	pip install --no-cache-dir --find-links=build/wheel --no-index dist/trivialsec_common-*-py2.py3-none-any.whl

install-dev: ## setup for development of this project
	pip install -q -U pip setuptools wheel awscli semgrep
	pip install -q -U --no-cache-dir --isolated -r requirements.txt

lint: ## checks code quality
	pylint --jobs=0 --persistent=y --errors-only trivialsec/**/*.py
	semgrep -q --strict --timeout=0 --config=p/ci --lang=py trivialsec/**/*.py
	semgrep -q --strict --config p/minusworld.flask-xss --lang=py trivialsec/**/*.py

package: wheel ## packages distribution
	tar -ckzf build.tgz build/wheel
	ls -l --block-size=M build.tgz

package-local: package ## packages distribution for local dev
	mkdir -p $(LOCAL_CACHE)
	cp -fu dist/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl $(LOCAL_CACHE)/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl
	cp -fu build.tgz $(LOCAL_CACHE)/build.tgz
	$(CMD_AWS) s3 cp --only-show-errors dist/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl s3://trivialsec-assets/dev/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl

package-upload-deps: ## packages distribution deps for local dev
	$(CMD_AWS) s3 cp --only-show-errors build.tgz s3://trivialsec-assets/dev/$(COMMON_VERSION)/build.tgz

package-upload: package ## uploads distribution to s3
	$(CMD_AWS) s3 cp --only-show-errors dist/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl s3://trivialsec-assets/deploy-packages/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl
	$(CMD_AWS) s3 cp --only-show-errors build.tgz s3://trivialsec-assets/deploy-packages/$(COMMON_VERSION)/build.tgz
