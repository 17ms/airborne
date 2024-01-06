#pragma once

#include <windows.h>

#include <fstream>
#include <string>
#include <vector>

std::vector<BYTE> ReadFromFile(const std::string &filename);
void WriteToFile(const std::string &filename, const std::vector<BYTE> &data);
