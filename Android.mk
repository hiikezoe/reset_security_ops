LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := main.c
LOCAL_MODULE := reset_security_ops
LOCAL_MODULE_TAGS := optional
LOCAL_LDFLAGS := --static
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES += libcutils libc

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := nonfixed_main.c
LOCAL_MODULE := reset_security_ops_nonfixed
LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)
