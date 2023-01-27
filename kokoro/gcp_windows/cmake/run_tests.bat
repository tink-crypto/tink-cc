SETLOCAL ENABLEDELAYEDEXPANSION

SET CMAKE_BIN="C:\Program Files\CMake\bin\cmake.exe"
SET CTEST_BIN="C:\Program Files\CMake\bin\ctest.exe"
SET CTEST_OUTPUT_ON_FAILURE=1

IF EXIST %KOKORO_ARTIFACTS_DIR%\git\tink_cc (
  SET WORKSPACE_DIR=%KOKORO_ARTIFACTS_DIR%\git\tink_cc
) ELSE IF EXIST %KOKORO_ARTIFACTS_DIR%\github\tink_cc (
  SET WORKSPACE_DIR=%KOKORO_ARTIFACTS_DIR%\github\tink_cc
)

CD !WORKSPACE_DIR!
if %errorlevel% neq 0 EXIT /B 1

MKDIR "build"
CD "build"

%CMAKE_BIN% -G"Visual Studio 15 2017 Win64" -S .. -B . ^
  -DCMAKE_CXX_STANDARD_REQUIRED=ON ^
  -DCMAKE_CXX_STANDARD=14 ^
  -DTINK_BUILD_TESTS=ON
IF %errorlevel% neq 0 EXIT /B 1

%CMAKE_BIN% --build . --config Debug --parallel 4
IF %errorlevel% neq 0 EXIT /B 1

%CTEST_BIN% -C Debug
IF %errorlevel% neq 0 EXIT /B 1

EXIT /B 0
