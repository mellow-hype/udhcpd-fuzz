ifdef AFL_USE_ASAN
export AFL_USE_ASAN
endif
all:
	+$(MAKE) -C src

install: all
	+$(MAKE) -C src install

clean:
	+$(MAKE) -C src clean