// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstddef>
#include <string>
#define LOW 0
#define HIGH 1
#define INPUT_PULLUP 2
extern bool jumperEnabled;
inline void pinMode(uint8_t, uint8_t) {}
inline int digitalRead(uint8_t) { return jumperEnabled ? LOW : HIGH; }
inline unsigned long millis() { return 1; }
inline void delay(unsigned long) {}
struct FakeSerial {
  std::string input;
  void begin(unsigned long) {}
  int available() { return !input.empty(); }
  int read() { int v = (unsigned char)input.front(); input.erase(0, 1); return v; }
  void print(const char *text);
  size_t write(char ch);
};
extern FakeSerial Serial;
