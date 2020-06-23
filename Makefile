CLANG_FORMAT := clang-format
ALL_SRCS := $(shell \
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
format: clang-format cmake-format

.PHONY: clang-format
clang-format:
	$(CLANG_FORMAT) -i -style=file $(ALL_SRCS)
	git diff --exit-code

.PHONY: cmake-format
cmake-format:
	cmake-format -i $(ALL_LISTFILES)
	git diff --exit-code
