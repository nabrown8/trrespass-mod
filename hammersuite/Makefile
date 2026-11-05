SDIR=src
IDIR=$(SDIR)/include
LDIR=lib
BUILD=obj
ODIR=src/.obj
DATA_DIR=$(PWD)/data/

CFLAGS=-I$(IDIR) -msse4.2 -ggdb -DDATA_DIR=\"$(DATA_DIR)\" -fsanitize=address,undefined -fstack-protector-all -pthread -g -O3 -MMD -MP
# CXX=g++
LDFLAGS=

OUT=tester
TEST_OUT=tester_test
PINGPONG_OUT=tester_pingpong

LDEPS=

GB_PAGE=/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
HUGEPAGE=/mnt/huge

all: $(OUT) $(TEST_OUT) $(PINGPONG_OUT)
.PHONY: clean


SOURCES := $(wildcard $(SDIR)/*.c)
OBJECTS := $(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(SOURCES))

# hammer-suite.c, test-suite.c, and double-pingpong.c all define the same
# symbols (test-suite.c and double-pingpong.c are forks of hammer-suite.c),
# so no two of them can ever be linked into the same binary: tester is
# built without test-suite.o/double-pingpong.o, tester_test without
# hammer-suite.o/double-pingpong.o, and tester_pingpong without
# hammer-suite.o/test-suite.o.
MAIN_OBJECTS     := $(filter-out $(ODIR)/test-suite.o $(ODIR)/double-pingpong.o, $(OBJECTS))
TEST_OBJECTS     := $(filter-out $(ODIR)/hammer-suite.o $(ODIR)/double-pingpong.o, $(OBJECTS))
PINGPONG_OBJECTS := $(filter-out $(ODIR)/hammer-suite.o $(ODIR)/test-suite.o, $(OBJECTS))


$(ODIR)/%.o: $(SDIR)/%.c
	mkdir -p $(ODIR)
	$(CXX) -o $@ -c $< $(CFLAGS) $(LDFLAGS) $(LDEPS)


$(OUT): $(MAIN_OBJECTS)
	mkdir -p $(BUILD)
	$(CXX) -o $(BUILD)/$@ $^ $(CFLAGS) $(LDFLAGS) $(LDEPS)
	chmod +x $(BUILD)/$@

$(TEST_OUT): $(TEST_OBJECTS)
	mkdir -p $(BUILD)
	$(CXX) -o $(BUILD)/$@ $^ $(CFLAGS) $(LDFLAGS) $(LDEPS)
	chmod +x $(BUILD)/$@

$(PINGPONG_OUT): $(PINGPONG_OBJECTS)
	mkdir -p $(BUILD)
	$(CXX) -o $(BUILD)/$@ $^ $(CFLAGS) $(LDFLAGS) $(LDEPS)
	chmod +x $(BUILD)/$@

-include $(OBJECTS:.o=.d)

clean:
	rm -rf $(BUILD)
	rm -rf $(ODIR)

setup:
	echo "Mounting hugetlbfs"
	echo 2 | sudo tee -a $(GB_PAGE)
	@if ! [ -d $(HUGEPAGE) ]; then\
		sudo mkdir $(HUGEPAGE);\
		sudo mount -t hugetlbfs  -o pagesize=1G none $(HUGEPAGE);\
		sudo chown pit:pit $(HUGEPAGE);\
	fi


teardown:
	@if [ -d $(HUGEPAGE) ]; then\
		sudo umount -f $(HUGEPAGE);\
		sudo rm -r $(HUGEPAGE);\
	fi
	echo 0 | sudo tee -a $(GB_PAGE)

run:
	sudo $(BUILD)/$(OUT)
