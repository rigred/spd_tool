// SPDX-License-Identifier: MIT
// Host simulator compiles the actual reference sketch against bounded fake IO.
#include "Arduino.h"
#include "Wire.h"
#include <iostream>
#include <fstream>
bool jumperEnabled = false;
FakeSerial Serial;
FakeWire Wire;
void FakeSerial::print(const char *text) { std::cout << text; }
size_t FakeSerial::write(char ch) { std::cout << ch; if (ch=='\n') std::cout.flush(); return 1; }
#include "../../firmware/spd_bridge/spd_bridge.ino"
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  std::ifstream image(argv[1], std::ios::binary);
  image.read(reinterpret_cast<char *>(Wire.memory), 256);
  if (image.gcount()!=256) return 3;
  jumperEnabled = std::string(argv[2]) == "enabled";
  setup();
  std::string line;
  while (std::getline(std::cin, line)) { Serial.input = line + '\n'; loop(); }
  return 0;
}
