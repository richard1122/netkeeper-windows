#pragma once
#include <stdexcept>
typedef uint8_t sxbyte;

class SXException:public std::runtime_error {
public:
	SXException(const std::string &msg) : std::runtime_error("SX error " + msg) {};
};