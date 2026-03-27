CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE
BIN_DIR := bin
SRC_DIR := src

TARGETS := \
	$(BIN_DIR)/sensor \
	$(BIN_DIR)/rpi_gateway \
	$(BIN_DIR)/controller \
	$(BIN_DIR)/actuator \
	$(BIN_DIR)/plant \
	$(BIN_DIR)/cps_maintd \
	$(BIN_DIR)/cps_maint_client \
	$(BIN_DIR)/attacker_bias \
	$(BIN_DIR)/attacker_delay \
	$(BIN_DIR)/attacker_replay

.PHONY: all clean

all: $(TARGETS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/sensor: $(SRC_DIR)/sensor.c $(SRC_DIR)/common.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/sensor.c -lm

$(BIN_DIR)/rpi_gateway: $(SRC_DIR)/rpi_gateway.c $(SRC_DIR)/common.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/rpi_gateway.c -lm

$(BIN_DIR)/controller: $(SRC_DIR)/controller.c $(SRC_DIR)/common.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/controller.c -lm

$(BIN_DIR)/actuator: $(SRC_DIR)/actuator.c $(SRC_DIR)/common.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/actuator.c -lm

$(BIN_DIR)/plant: $(SRC_DIR)/plant.c $(SRC_DIR)/common.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/plant.c -lm

$(BIN_DIR)/cps_maintd: $(SRC_DIR)/cps_maintd.c $(SRC_DIR)/common.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/cps_maintd.c -lm

$(BIN_DIR)/cps_maint_client: $(SRC_DIR)/cps_maint_client.c $(SRC_DIR)/common.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/cps_maint_client.c -lm

$(BIN_DIR)/attacker_bias: $(SRC_DIR)/attacker_bias.c $(SRC_DIR)/common.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/attacker_bias.c

$(BIN_DIR)/attacker_delay: $(SRC_DIR)/attacker_delay.c $(SRC_DIR)/common.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/attacker_delay.c

$(BIN_DIR)/attacker_replay: $(SRC_DIR)/attacker_replay.c $(SRC_DIR)/common.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/attacker_replay.c

clean:
	rm -rf $(BIN_DIR)
