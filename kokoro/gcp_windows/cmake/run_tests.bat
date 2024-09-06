:: Copyright 2023 Google LLC
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.
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

%CMAKE_BIN% -G"Visual Studio 17 2022" -A x64 -S .. -B . ^
  -DCMAKE_CXX_STANDARD_REQUIRED=ON ^
  -DCMAKE_CXX_STANDARD=14 ^
  -DTINK_BUILD_TESTS=ON
IF %errorlevel% neq 0 EXIT /B 1

%CMAKE_BIN% --build . --config Debug --parallel 4
IF %errorlevel% neq 0 EXIT /B 1

%CTEST_BIN% -C Debug
IF %errorlevel% neq 0 EXIT /B 1

EXIT /B 0
