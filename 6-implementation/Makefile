OUT = out/plots/ out/csv/
OPTIONS = distrib convolution fourier hadamard 

target: build

build:
	@ cargo build

run:
	@ cargo run

.PHONY: clean

clean:
	@ cargo clean

DEMO_BINS = demo_zp demo_p256_no_tag demo_p256_tag bench_p256

bin_%:
	@echo "Running demo $*..."
	@cargo run --bin $*

$(foreach bin,$(DEMO_BINS),$(eval $(bin): bin_$(bin)))