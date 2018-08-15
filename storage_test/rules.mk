# Copyright (C) 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

KEYMASTER_ROOT := $(LOCAL_DIR)/../../../system/keymaster

MODULE_SRCS += \
    $(LOCAL_DIR)/manifest.c \
    $(LOCAL_DIR)/main.cpp \
    $(LOCAL_DIR)/../secure_storage.cpp \
    $(KEYMASTER_ROOT)/logger.cpp

MODULE_DEPS += \
    app/trusty \
    lib/libc-trusty \
    lib/libstdc++-trusty \
    trusty/user/base/lib/rng \
    trusty/user/base/lib/storage \

include make/module.mk
