@echo off
mkdir build
cd build
cmake ..
cls
cmake --build . --config Release