#pragma once

#include <ntdef.h>

#define PF_WFP_DEVICE_NAME L"\\Device\\ProxiFyreWfp"
#define PF_WFP_DOS_DEVICE_NAME L"\\DosDevices\\ProxiFyreWfp"
#define PF_WFP_USER_DEVICE_NAME L"\\\\.\\ProxiFyreWfp"

#define PF_WFP_PROTOCOL_VERSION 1
#define PF_WFP_MAX_ADDRESS_BYTES 16
#define PF_WFP_MAX_EVENT_QUEUE 4096

#define PF_WFP_IOCTL_GET_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_DATA)
#define PF_WFP_IOCTL_COMPLETE_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_DATA)

typedef struct _PF_WFP_FLOW_EVENT
{
    UINT64 EventId;
    UINT32 ProcessId;
    UINT16 AddressFamily;
    UINT8 Protocol;
    UINT8 Reserved0;
    UINT8 LocalAddress[PF_WFP_MAX_ADDRESS_BYTES];
    UINT8 RemoteAddress[PF_WFP_MAX_ADDRESS_BYTES];
    UINT16 LocalPort;
    UINT16 RemotePort;
    UINT32 RemoteScopeId;
    UINT32 Flags;
    UINT32 InterfaceIndex;
    UINT32 SubInterfaceIndex;
} PF_WFP_FLOW_EVENT, *PPF_WFP_FLOW_EVENT;

typedef struct _PF_WFP_VERDICT
{
    UINT64 EventId;
    UINT32 Decision;
    UINT32 Reserved;
} PF_WFP_VERDICT, *PPF_WFP_VERDICT;

#define PF_WFP_DECISION_PERMIT 0
#define PF_WFP_DECISION_BLOCK 1
