# NOTE(ww): Make sure to update the platform tag in .github/workflows/release.yml
# if you update this image. The two MUST remain in sync to ensure correct wheel builds.
MANYLINUX_IMAGE := quay.io/pypa/manylinux2014_x86_64
CLANG_FORMAT := clang-format
ALL_PY_SRCS := $(shell \
	find . \
		-type f \
		\( -path */third_party/* \) -prune \
		-o -name '*.py' \
		-print \
)
ALL_CXX_SRCS := $(shell \
	find . \
		-type f \
		\( -path */third_party/* \) -prune \
		-o \( -name '*.cpp' -o -name '*.h' \) \
		-print \
)
ALL_LISTFILES := $(shell \
	find . \
		-type f \
		\( -path */third_party/* \) -prune \
		-o \( -name 'CMakeLists.txt' -o -name '*.cmake' \) \
		-print \
)

.PHONY: all
all:
	@echo "This Makefile does not build anything."

.PHONY: format
format: blacken clang-format cmake-format

.PHONY: blacken
blacken:
	black $(ALL_PY_SRCS)
	git diff --exit-code

.PHONY: clang-format
clang-format:
	$(CLANG_FORMAT) -i -style=file $(ALL_CXX_SRCS)
	git diff --exit-code

.PHONY: cmake-format
cmake-format:
	cmake-format -i $(ALL_LISTFILES)
	git diff --exit-code

.PHONY: manylinux
manylinux:
	docker pull $(MANYLINUX_IMAGE)
	# NOTE(ww): We pass PYTHON through the environment here for the XED
	# build, which is Python based. The version doesn't matter, as long
	# as mbuild itself is okay with it. It is **not** related to the wheel
	# builds, which happen subsequently.
	docker run -e PYTHON=/opt/python/cp38-cp38/bin/python \
		--rm -v $(shell pwd):/io $(MANYLINUX_IMAGE) \
		/io/scripts/bootstrap.sh
	docker run \
		--rm -v $(shell pwd):/io $(MANYLINUX_IMAGE) \
		/opt/python/cp35-cp35m/bin/pip wheel /io -w /io/dist
	docker run \
		--rm -v $(shell pwd):/io $(MANYLINUX_IMAGE) \
		/opt/python/cp36-cp36m/bin/pip wheel /io -w /io/dist
	docker run \
		--rm -v $(shell pwd):/io $(MANYLINUX_IMAGE) \
		/opt/python/cp37-cp37m/bin/pip wheel /io -w /io/dist
	docker run \
		--rm -v $(shell pwd):/io $(MANYLINUX_IMAGE) \
		/opt/python/cp38-cp38/bin/pip wheel /io -w /io/dist
