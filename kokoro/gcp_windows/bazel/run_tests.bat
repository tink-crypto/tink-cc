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

IF EXIST %KOKORO_ARTIFACTS_DIR%\git\tink_cc (
  SET WORKSPACE_DIR=%KOKORO_ARTIFACTS_DIR%\git\tink_cc
) ELSE IF EXIST %KOKORO_ARTIFACTS_DIR%\github\tink_cc (
  SET WORKSPACE_DIR=%KOKORO_ARTIFACTS_DIR%\github\tink_cc
)


IF "%TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET%"=="" (
  SET CACHE_FLAGS=
) ELSE (
  SET CACHE_FLAGS=--remote_cache=https://storage.googleapis.com/%TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET%/bazel/windows --google_credentials=%TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY%
)

CD !WORKSPACE_DIR!
if %errorlevel% neq 0 EXIT /B 1

ECHO Build started at %TIME%
@REM See https://github.com/protocolbuffers/protobuf/issues/12947 and
@REM  https://bazel.build/configure/windows#long-path-issues for why
@REM --output_base=C:\O is needed.
bazel --output_base=C:\O build %CACHE_FLAGS% ...
IF %errorlevel% neq 0 EXIT /B 1
ECHO Build completed at %TIME%

ECHO Test started at %TIME%
bazel --output_base=C:\O test %CACHE_FLAGS% --strategy=TestRunner=standalone --test_output=errors -- ...
IF %errorlevel% neq 0 EXIT /B 1
ECHO Test completed at %TIME%

EXIT /B 0
