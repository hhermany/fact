# Compila o programa BPF e o carregador (clang/libbpf do host).
ARCH_INC ?= /usr/include/$(shell uname -m)-linux-gnu
all: agentnet_policy.bpf.o agentnet_policy
agentnet_policy.bpf.o: agentnet_policy.bpf.c
	clang -O2 -g -target bpf -I$(ARCH_INC) -c $< -o $@
agentnet_policy: agentnet_policy.c
	gcc -O2 -Wall -o $@ $< -lbpf
clean:
	rm -f agentnet_policy.bpf.o agentnet_policy
