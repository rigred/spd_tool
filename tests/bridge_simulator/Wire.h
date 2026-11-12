// SPDX-License-Identifier: MIT
#pragma once
#include <vector>
#include <cstdint>
#include <cstddef>
#define WIRE_HAS_TIMEOUT 1
struct FakeWire {
  uint8_t memory[256] = {};
  std::vector<uint8_t> tx, rx;
  uint8_t address = 0, offset = 0;
  bool timeout = false;
  unsigned long writes = 0;
  void begin() {}
  void setClock(unsigned long) {}
  void setWireTimeout(unsigned long, bool) {}
  void clearWireTimeoutFlag() { timeout = false; }
  bool getWireTimeoutFlag() { return timeout; }
  void beginTransmission(uint8_t a) { address = a; tx.clear(); }
  size_t write(uint8_t value) { tx.push_back(value); return 1; }
  uint8_t endTransmission(bool = true) {
    if (address != 0x50 || tx.empty()) return 2;
    offset = tx[0];
    if (tx.size() == 2) { memory[offset] = tx[1]; ++writes; }
    return 0;
  }
  uint8_t requestFrom(uint8_t a, uint8_t count, uint8_t) {
    rx.clear();
    if (a != 0x50) return 0;
    for (uint8_t i = 0; i < count; ++i) rx.push_back(memory[(offset+i)&255]);
    return count;
  }
  int available() { return !rx.empty(); }
  int read() { int v=rx.front(); rx.erase(rx.begin()); return v; }
};
extern FakeWire Wire;
