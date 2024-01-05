#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <fstream>

std::vector<BYTE> ReadFromFile(const std::string &filename);
void WriteToFile(const std::string &filename, const std::vector<BYTE> &data);
