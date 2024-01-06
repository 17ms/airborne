#include "futils.hpp"

std::vector<BYTE> ReadFromFile(const std::string &filename) {
  std::ifstream file(filename, std::ios::binary);
  std::vector<BYTE> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  file.close();

  return data;
}

void WriteToFile(const std::string &filename, const std::vector<BYTE> &data) {
  std::ofstream file(filename, std::ios::binary);
  file.write(reinterpret_cast<const char *>(data.data()), data.size());
  file.close();
}
