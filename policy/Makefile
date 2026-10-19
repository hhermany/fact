# Builds the BPF program and the loader (host clang/libbpf).
ARCH_INC ?= /usr/include/$(shell uname -m)-linux-gnu
all: fact_policy.bpf.o fact_policy
fact_policy.bpf.o: fact_policy.bpf.c
	clang -O2 -g -target bpf -I$(ARCH_INC) -c $< -o $@
fact_policy: fact_policy.c
	gcc -O2 -Wall -o $@ $< -lbpf
clean:
	rm -f fact_policy.bpf.o fact_policy
