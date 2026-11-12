// SPDX-License-Identifier: MIT
// SPD1 USB serial / I2C reference bridge. Requires Wire timeout support.
#include <Arduino.h>
#include <Wire.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#if !defined(WIRE_HAS_TIMEOUT)
#error "Use a Wire implementation with WIRE_HAS_TIMEOUT; unbounded I2C is unsupported"
#endif

const uint8_t WRITE_ENABLE_PIN = 4; // Ground to permit writes; open = read-only.
char input[160];
size_t used = 0;
bool overflowed = false;
unsigned long lastByte = 0;

uint16_t crc16(const char *text) {
  uint16_t crc = 0;
  while (*text) {
    crc ^= (uint16_t)(uint8_t)*text++ << 8;
    for (uint8_t i = 0; i < 8; ++i)
      crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1;
  }
  return crc;
}

void respond(unsigned long seq, const char *status, const char *value) {
  char body[128], suffix[8];
  if (value && *value) snprintf(body, sizeof(body), "SPD1 %lu %s %s", seq, status, value);
  else snprintf(body, sizeof(body), "SPD1 %lu %s", seq, status);
  snprintf(suffix, sizeof(suffix), "*%04X", crc16(body));
  Serial.print(body); Serial.print(suffix); Serial.write('\n');
}

bool number(const char *text, unsigned long &result, uint8_t base = 10) {
  if (!text || !*text || *text == '-' || *text == '+') return false;
  for (const char *p = text; *p; ++p)
    if (base == 10 ? (*p < '0' || *p > '9') : !isxdigit((unsigned char)*p)) return false;
  if (strlen(text) > (base == 10 ? 9u : 4u)) return false;
  char *end;
  result = strtoul(text, &end, base);
  return *end == 0;
}

bool readSPD(uint8_t address, uint8_t offset, uint8_t count, uint8_t *data) {
  Wire.clearWireTimeoutFlag();
  Wire.beginTransmission(address);
  if (Wire.write(offset) != 1 || Wire.endTransmission(false) != 0) return false;
  uint8_t got = Wire.requestFrom(address, count, (uint8_t)true);
  if (got != count || Wire.getWireTimeoutFlag()) {
    while (Wire.available()) Wire.read();
    return false;
  }
  for (uint8_t i = 0; i < count; ++i) {
    if (!Wire.available()) return false;
    data[i] = Wire.read();
  }
  return true;
}

void command(char *line) {
  char *star = strrchr(line, '*');
  unsigned long supplied;
  if (!star || strlen(star + 1) != 4 || !number(star + 1, supplied, 16)) return;
  *star = 0;
  if (crc16(line) != supplied) return; // Bad frames never reach the bus.
  char *save;
  char *magic = strtok_r(line, " ", &save);
  char *sequence = strtok_r(NULL, " ", &save);
  char *op = strtok_r(NULL, " ", &save);
  unsigned long seq;
  if (!magic || strcmp(magic, "SPD1") || !number(sequence, seq) || !op) return;
  if (!strcmp(op, "HELLO")) {
    if (strtok_r(NULL, " ", &save)) { respond(seq, "ERR", "ARGS"); return; }
    respond(seq, "OK", digitalRead(WRITE_ENABLE_PIN) == LOW ? "256 16 1 1" : "256 16 1 0");
    return;
  }
  char *address = strtok_r(NULL, " ", &save);
  char *offset = strtok_r(NULL, " ", &save);
  char *value = strtok_r(NULL, " ", &save);
  unsigned long addr, pos, arg;
  bool reading = !strcmp(op, "READ"), writing = !strcmp(op, "WRITE");
  if ((!reading && !writing) || !number(address, addr) || !number(offset, pos)
      || !number(value, arg, writing ? 16 : 10) || strtok_r(NULL, " ", &save)
      || addr < 0x50 || addr > 0x57 || pos > 255) {
    respond(seq, "ERR", "ARGS"); return;
  }
  if (reading) {
    if (arg < 1 || arg > 16 || pos + arg > 256) { respond(seq, "ERR", "RANGE"); return; }
    uint8_t data[16]; char hex[33];
    if (!readSPD(addr, pos, arg, data)) { respond(seq, "ERR", "I2C_READ"); return; }
    for (uint8_t i = 0; i < arg; ++i) snprintf(hex + 2*i, 3, "%02X", data[i]);
    respond(seq, "OK", hex);
  } else {
    if (arg > 255 || digitalRead(WRITE_ENABLE_PIN) != LOW) { respond(seq, "ERR", "WRITE_LOCKED"); return; }
    uint8_t header[3];
    if (strlen(value) != 2 || !readSPD(addr, 0, 3, header)) { respond(seq, "ERR", "HEADER"); return; }
    uint8_t type = header[2];
    if (!(type == 4 || type == 7 || type == 8 || type == 11)
        || (pos == 2 && arg != type)) { respond(seq, "ERR", "MEMORY_TYPE"); return; }
    unsigned int capacity = type == 11 ? ((header[0] & 0x70) == 0x10 ? 256 : 0)
        : (header[1] == 7 ? 128 : header[1] == 8 ? 256 : 0);
    if (pos >= capacity) { respond(seq, "ERR", "CAPACITY"); return; }
    if (digitalRead(WRITE_ENABLE_PIN) != LOW) { respond(seq, "ERR", "WRITE_LOCKED"); return; }
    Wire.clearWireTimeoutFlag();
    Wire.beginTransmission(addr);
    size_t queued = Wire.write((uint8_t)pos);
    queued += Wire.write((uint8_t)arg);
    uint8_t status = Wire.endTransmission(true);
    if (queued != 2 || status || Wire.getWireTimeoutFlag()) { respond(seq, "ERR", "I2C_WRITE_UNKNOWN"); return; }
    delay(20); // Single-byte programming: no page-size assumptions or retries.
    uint8_t actual;
    if (!readSPD(addr, pos, 1, &actual) || actual != arg) { respond(seq, "ERR", "VERIFY"); return; }
    respond(seq, "OK", "");
  }
}

void setup() {
  pinMode(WRITE_ENABLE_PIN, INPUT_PULLUP);
  Serial.begin(115200);
  Wire.begin(); Wire.setClock(100000);
  Wire.setWireTimeout(25000, true);
}

void loop() {
  if (used && millis() - lastByte > 1000) { used = 0; overflowed = false; }
  while (Serial.available()) {
    char ch = Serial.read(); lastByte = millis();
    if (ch == '\n') {
      if (!overflowed) { input[used] = 0; command(input); }
      used = 0; overflowed = false;
    } else if (used < sizeof(input) - 1 && !overflowed) input[used++] = ch;
    else overflowed = true;
  }
}
