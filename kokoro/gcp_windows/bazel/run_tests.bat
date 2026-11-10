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

:: Unique hex string of length 20
@ECHO ================================================================================
@ECHO Tink Script ID: fece440a457ddbbdb063 (to quickly find the script from logs)
@ECHO ================================================================================

SETLOCAL ENABLEDELAYEDEXPANSION

IF EXIST %KOKORO_ARTIFACTS_DIR%\git\tink_cc (
  SET WORKSPACE_DIR=%KOKORO_ARTIFACTS_DIR%\git\tink_cc
) ELSE IF EXIST %KOKORO_ARTIFACTS_DIR%\github\tink_cc (
  SET WORKSPACE_DIR=%KOKORO_ARTIFACTS_DIR%\github\tink_cc
)


IF "%TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET%"=="" (
  SET CACHE_FLAGS=
) ELSE (
  SET CACHE_FLAGS=--remote_cache=https://storage.googleapis.com/%TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET%/bazel/windows --google_credentials=%TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY% --remote_download_minimal
)

CD !WORKSPACE_DIR!
if %errorlevel% neq 0 EXIT /B 1

ECHO Build and test started at %TIME%
@REM See https://github.com/protocolbuffers/protobuf/issues/12947 and
@REM  https://bazel.build/configure/windows#long-path-issues for why
@REM --output_base=C:\O is needed.
@REM --nobuild_tests_only ensures all non-test targets in '...' are built too.
bazel --output_base=C:\O test --nobuild_tests_only %CACHE_FLAGS% --strategy=TestRunner=standalone --test_output=errors --define=protobuf_allow_msvc=true -- ...
IF %errorlevel% neq 0 EXIT /B 1
ECHO Build and test completed at %TIME%

EXIT /B 0
